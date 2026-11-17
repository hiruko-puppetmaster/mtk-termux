from __future__ import annotations

import struct
import unittest
from unittest import mock

from core.errors import AuthError
from core.protocols import (
    BROM_SYNC_RESPONSE,
    DT_MESSAGE,
    DT_PROTOCOL_FLOW,
    XFLASH_MAGIC,
    BromProtocol,
    DAXMLProtocol,
    DaFileRequest,
    TargetConfig,
    XFlashV5,
    build_xml_command,
    parse_xml_fields,
)
from tests.helpers import FakeTransport


class BromTests(unittest.TestCase):
    def test_sync(self):
        transport = FakeTransport(BROM_SYNC_RESPONSE)
        brom = BromProtocol(transport)
        brom.sync()
        self.assertEqual(bytes(transport.writes), b"\xa0\x0a\x50\x05")

    def test_get_hw_code(self):
        transport = FakeTransport(b"\xfd\x07\x66\x00\x01")
        brom = BromProtocol(transport)
        hw = brom.get_hw_code()
        self.assertEqual(hw.code, 0x0766)
        self.assertEqual(hw.version, 0x0001)

    def test_read32(self):
        address = 0x10000000
        count = 2
        values = [0x11223344, 0xAABBCCDD]
        reads = (
            b"\xd1"
            + struct.pack(">I", address)
            + struct.pack(">I", count)
            + b"\x00\x00"
            + struct.pack(">II", *values)
            + b"\x00\x00"
        )
        transport = FakeTransport(reads)
        brom = BromProtocol(transport)
        self.assertEqual(brom.read32(address, count), values)
        self.assertEqual(
            bytes(transport.writes),
            b"\xd1" + struct.pack(">II", address, count),
        )

    def test_write32(self):
        address = 0x10000000
        values = [0x11223344, 0xAABBCCDD]
        reads = (
            b"\xd4"
            + struct.pack(">I", address)
            + struct.pack(">I", len(values))
            + b"\x00\x00"
            + struct.pack(">II", *values)
            + b"\x00\x00"
        )
        transport = FakeTransport(reads)
        brom = BromProtocol(transport)
        brom.write32(address, values)
        self.assertIn(struct.pack(">I", address), bytes(transport.writes))

    def test_target_config(self):
        # SBC + SLA + DAA, status 0.
        reads = b"\xd8" + struct.pack(">IH", 0b111, 0)
        brom = BromProtocol(FakeTransport(reads))
        target = brom.get_target_config()
        self.assertTrue(target.sbc)
        self.assertTrue(target.sla)
        self.assertTrue(target.daa)
        self.assertFalse(target.cert)

    def test_send_auth_consumes_one_trailer(self):
        payload = b"ABCD"
        reads = (
            b"\xe2"
            + struct.pack(">I", len(payload))
            + b"\x00\x00"
            + b"\x00\x00"  # checksum is accepted as zero
            + b"\x00\x00"
        )
        transport = FakeTransport(reads)
        brom = BromProtocol(transport)
        with mock.patch("core.protocols.time.sleep"):
            brom.send_auth(payload)
        self.assertEqual(len(transport.read_buffer), 0)
        written = bytes(transport.writes)
        self.assertTrue(written.startswith(b"\xe2" + struct.pack(">I", len(payload))))
        self.assertIn(payload, written)
        self.assertGreaterEqual(transport.zero_writes, 1)

    def test_authenticate_sla_target_does_not_probe_sla(self):
        payload = b"ABCD"
        reads = (
            b"\xe2"
            + struct.pack(">I", len(payload))
            + b"\x00\x00"
            + b"\x00\x00"
            + b"\x00\x00"
        )
        transport = FakeTransport(reads)
        brom = BromProtocol(transport)
        with mock.patch("core.protocols.time.sleep"):
            result = brom.authenticate(
                auth=payload, target=TargetConfig.from_raw(0b010)
            )
        self.assertTrue(result.auth_sent)
        self.assertFalse(result.sla_passed)
        self.assertNotIn(b"\xe3", bytes(transport.writes))

    def test_send_da_requires_sla_signer_on_1d0d(self):
        data = b"D" * 0x10
        reads = (
            b"\xd7"
            + struct.pack(">I", 0x40000000)
            + struct.pack(">I", len(data))
            + struct.pack(">I", 0)
            + b"\x1d\x0d"
        )
        brom = BromProtocol(FakeTransport(reads))
        with self.assertRaises(AuthError):
            brom.send_da(0x40000000, data)

    def test_send_da_packet_and_flush(self):
        data = b"D" * 0x2000
        reads = (
            b"\xd7"
            + struct.pack(">I", 0x40000000)
            + struct.pack(">I", len(data))
            + struct.pack(">I", 0)
            + b"\x00\x00"
            + b"\x00\x00"
            + b"\x00\x00"
        )
        transport = FakeTransport(reads)
        brom = BromProtocol(transport)
        with mock.patch("core.protocols.time.sleep"):
            brom.send_da(0x40000000, data, signature_length=0)
        self.assertEqual(len(transport.read_buffer), 0)
        written = bytes(transport.writes)
        expected_header = (
            b"\xd7"
            + struct.pack(">I", 0x40000000)
            + struct.pack(">I", len(data))
            + struct.pack(">I", 0)
        )
        self.assertTrue(written.startswith(expected_header))
        self.assertTrue(written.endswith(data))
        # One flush at the 8 KiB boundary and one terminating packet.
        self.assertGreaterEqual(transport.zero_writes, 2)


class XFlashTests(unittest.TestCase):
    def test_send(self):
        transport = FakeTransport()
        x = XFlashV5(transport)
        x.send_u32(0x434E5953)
        self.assertEqual(
            bytes(transport.writes),
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 4)
            + struct.pack("<I", 0x434E5953),
        )

    def test_message_packet(self):
        payload = b"hello"
        raw = (
            struct.pack("<III", XFLASH_MAGIC, DT_MESSAGE, len(payload) + 4)
            + struct.pack("<I", 7)
            + payload
        )
        x = XFlashV5(FakeTransport(raw))
        packet = x.read_packet()
        self.assertEqual(packet.datatype, DT_MESSAGE)
        self.assertEqual(packet.priority, 7)
        self.assertEqual(packet.data, payload)

    def test_setup_env_packet_order(self):
        status_packet = (
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 4)
            + struct.pack("<I", 0)
        )
        transport = FakeTransport(status_packet)
        x = XFlashV5(transport)
        x.setup_env()
        written = bytes(transport.writes)
        expected_cmd = (
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 4)
            + struct.pack("<I", 0x010100)
        )
        expected_param = (
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 20)
            + struct.pack("<IIIII", 2, 2, 1, 0, 0)
        )
        self.assertEqual(written, expected_cmd + expected_param)

    def test_boot_to_packet_order(self):
        def status(value: int) -> bytes:
            return (
                struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 4)
                + struct.pack("<I", value)
            )

        data = b"stage2"
        transport = FakeTransport(
            status(0) + status(0) + status(0x434E5953)
        )
        x = XFlashV5(transport)
        x.boot_to(0x40000000, data, timeout_s=0)
        written = bytes(transport.writes)
        param_packet = (
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 16)
            + struct.pack("<QQ", 0x40000000, len(data))
        )
        data_packet = (
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, len(data)) + data
        )
        self.assertIn(param_packet + data_packet, written)
        self.assertTrue(written.startswith(struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 4)))

    def test_get_info_uses_device_ctrl(self):
        def packet(data: bytes) -> bytes:
            return (
                struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, len(data))
                + data
            )

        transport = FakeTransport(
            packet(b"\x00\x00\x00\x00")  # wrapper status
            + packet(b"\x00\x00\x00\x00")  # subcommand status
            + packet(b"EMMC")
            + packet(b"\x00\x00\x00\x00")  # final status
        )
        x = XFlashV5(transport)
        self.assertEqual(x.get_info(0x040001), b"EMMC")
        written = bytes(transport.writes)
        self.assertIn(
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 4)
            + struct.pack("<I", 0x010009),
            written,
        )
        self.assertIn(
            struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, 4)
            + struct.pack("<I", 0x040001),
            written,
        )


class XmlTests(unittest.TestCase):
    def test_build_and_parse(self):
        xml = build_xml_command(
            "DOWNLOAD-FILE",
            {"arg": {"checksum": "CHK_NO", "info": "2nd-DA"}},
        )
        self.assertIn("CMD:DOWNLOAD-FILE", xml)
        self.assertIn("<info>2nd-DA</info>", xml)
        command, fields = parse_xml_fields(xml)
        self.assertEqual(command, "CMD:DOWNLOAD-FILE")
        self.assertEqual(fields["info"], "2nd-DA")

    def test_escape(self):
        xml = build_xml_command("TEST", {"arg": {"x": "<&>"}})
        self.assertIn("&lt;&amp;&gt;", xml)
        self.assertNotIn("<x><&></x>", xml)

    def test_mem_length(self):
        request = DaFileRequest(
            "CMD:DOWNLOAD-FILE",
            source_file="MEM://0x40000000:0x1000",
        )
        self.assertEqual(request.length, 0x1000)


def _flow(data: bytes) -> bytes:
    return struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, len(data)) + data


def _text(text: str) -> bytes:
    return _flow(text.encode("utf-8") + b"\x00")


class XmlTransferTests(unittest.TestCase):
    def test_upload_file_single_chunk(self):
        payload = bytes(range(0x20))
        request = DaFileRequest(
            "CMD:DOWNLOAD-FILE",
            info="2nd-DA",
            source_file=f"MEM://0x40000000:{hex(len(payload))}",
            packet_length=0x20,
        )
        reads = (
            _text("OK")
            + _text("OK")
            + _text("OK")
            + _text(build_xml_command("END", {"result": "OK"}))
            + _text(build_xml_command("START"))
        )
        transport = FakeTransport(reads)
        protocol = DAXMLProtocol(transport)
        result = protocol.upload_file(request, payload)
        self.assertEqual(result.command, "CMD:START")
        self.assertTrue(result.ok)
        written = bytes(transport.writes)
        self.assertIn(payload, written)
        self.assertIn(b"OK@0x20", written)

    def test_upload_file_multi_chunk(self):
        payload = bytes(range(0x40))
        request = DaFileRequest(
            "CMD:DOWNLOAD-FILE",
            source_file=f"MEM://0x40000000:{hex(len(payload))}",
            packet_length=0x10,
        )
        reads = _text("OK")
        for _ in range(4):
            reads += _text("OK") + _text("OK")
        reads += _text(build_xml_command("END", {"result": "OK"}))
        reads += _text(build_xml_command("START"))
        transport = FakeTransport(reads)
        protocol = DAXMLProtocol(transport)
        protocol.upload_file(request, payload)
        written = bytes(transport.writes)
        for offset in range(0, len(payload), 0x10):
            self.assertIn(payload[offset : offset + 0x10], written)

    def test_upload_file_short_data(self):
        request = DaFileRequest(
            "CMD:DOWNLOAD-FILE",
            source_file="MEM://0x40000000:0x100",
        )
        transport = FakeTransport()
        protocol = DAXMLProtocol(transport)
        with self.assertRaises(Exception):
            protocol.upload_file(request, b"\x00" * 0x10)

    def test_download_file(self):
        payload = b"ABCDEFGH"
        request = DaFileRequest("CMD:UPLOAD-FILE")
        reads = _text(f"OK@{hex(len(payload))}") + _text("OK") + _flow(payload)
        transport = FakeTransport(reads)
        protocol = DAXMLProtocol(transport)
        self.assertEqual(protocol.download_file(request), payload)
        self.assertIn(b"OK", bytes(transport.writes))

    def test_download_file_bad_size(self):
        request = DaFileRequest("CMD:UPLOAD-FILE")
        transport = FakeTransport(_text("NOT-OK"))
        protocol = DAXMLProtocol(transport)
        with self.assertRaises(Exception):
            protocol.download_file(request)


if __name__ == "__main__":
    unittest.main()
