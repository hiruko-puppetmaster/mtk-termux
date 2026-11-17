from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from core.errors import AuthError, DaError
from core.options import AppOptions
from core.profiles import AssetDiscovery, ProfileStore
from core.protocols import (
    DT_PROTOCOL_FLOW,
    XFLASH_MAGIC,
    HwCode,
    TargetConfig,
    build_xml_command,
)
from core.session import DeviceSession
from termux_transport.usb_host import DeviceMode, UsbDeviceInfo
from tests.helpers import FakeTransport
from tests.test_da_loader import build_da


def write_preloader(path: Path) -> None:
    data = bytearray(0x400)
    marker = b"MTK_BLOADER_INFO_v12\x00"
    data[0x100 : 0x100 + len(marker)] = marker
    path.write_bytes(bytes(data))


class ValidateOnlyTests(unittest.TestCase):
    def test_valid_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            da = root / "DA.bin"
            preloader = root / "preloader.bin"
            auth = root / "device.auth"
            payload = root / "payload.bin"
            da.write_bytes(build_da())
            write_preloader(preloader)
            auth.write_bytes(b"A" * 64)
            payload.write_bytes(b"P" * 16)
            messages = DeviceSession.validate_only(
                AppOptions(
                    da=da,
                    preloader=preloader,
                    auth=auth,
                    payload=payload,
                    profiles_dir=root / "profiles",
                )
            )
        self.assertTrue(any("DA:" in m for m in messages))
        self.assertTrue(any("preloader:" in m for m in messages))
        self.assertTrue(any("auth:" in m for m in messages))
        self.assertTrue(any("payload:" in m for m in messages))

    def test_missing_da_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(DaError):
                DeviceSession.validate_only(
                    AppOptions(da=Path(tmp) / "missing.bin")
                )


class BundleResolutionTests(unittest.TestCase):
    def test_explicit_da_resolves_without_usb(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            da = root / "MTK_AllInOne_DA.bin"
            da.write_bytes(build_da())
            discovery = AssetDiscovery([root])
            discovery.dirs = [root]
            session = DeviceSession(
                AppOptions(da=da),
                store=ProfileStore([]),
                discovery=discovery,
            )
            bundle = session._resolve_bundle(
                HwCode(0x0766, 1), TargetConfig(raw=0)
            )
            session.close()
        self.assertEqual(bundle.da, da)
        self.assertIsNotNone(bundle.da_entry)
        self.assertEqual(bundle.da_entry.hw_code, 0x0766)

    def test_missing_da_raises(self):
        discovery = AssetDiscovery([])
        discovery.dirs = []
        session = DeviceSession(
            AppOptions(),
            store=ProfileStore([]),
            discovery=discovery,
        )
        with self.assertRaises(DaError):
            session._resolve_bundle(HwCode(0x0766, 1), TargetConfig(raw=0))
        session.close()


class FakeBrom:
    def __init__(self) -> None:
        self.sent_da: list[tuple[int, int, int]] = []
        self.jumped: list[int] = []

    def sync(self) -> None:
        pass

    def get_hw_code(self) -> HwCode:
        return HwCode(0x0766, 1)

    def get_target_config(self) -> TargetConfig:
        return TargetConfig(raw=0)

    def send_da(self, address: int, data: bytes, signature_length: int = 0) -> None:
        self.sent_da.append((address, len(data), signature_length))

    def jump_da(self, address: int, timeout_s: float = 0.0) -> None:
        self.jumped.append(address)


class ScriptedSession(DeviceSession):
    def __init__(self, transport: FakeTransport, **kwargs) -> None:
        super().__init__(**kwargs)
        self.transport = transport
        self.brom = FakeBrom()

    def open(self, device: UsbDeviceInfo):  # type: ignore[override]
        self.claimed = self.transport
        return self.transport


def _packet(data: bytes) -> bytes:
    return struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, len(data)) + data


def _text(text: str | bytes) -> bytes:
    if isinstance(text, str):
        text = text.encode("utf-8")
    return _packet(text + b"\x00")


def _start() -> bytes:
    return _text(build_xml_command("START"))


def _end_ok() -> bytes:
    return _text(build_xml_command("END", {"result": "OK"}))


def _ok_command() -> bytes:
    return _text("OK") + _end_ok() + _start()


def _download_request(address: int, length: int) -> bytes:
    xml = build_xml_command(
        "DOWNLOAD-FILE",
        {
            "arg": {
                "checksum": "CHK_NO",
                "info": "2nd-DA",
                "source_file": f"MEM://{hex(address)}:{hex(length)}",
                "packet_length": "0x1000",
            }
        },
        root_tag="host",
    )
    return _text(xml)


class SessionFlowTests(unittest.TestCase):
    def test_xml_da2_startup_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            da = Path(tmp) / "MTK_DA_V6.bin"
            da.write_bytes(build_da())
            reads = (
                _start()
                + _ok_command() * 4  # set-runtime-parameter + setup_hw_init
                + _text("OK")  # BOOT-TO accepted
                + _download_request(0x40100000, 0x70)
                + _text("OK") * 3  # upload length, chunk ack, chunk
                + _end_ok()
                + _start()
                + _ok_command() * 3  # post-DA2 setup_hw_init
            )
            transport = FakeTransport(reads)
            session = ScriptedSession(
                transport,
                options=AppOptions(da=da),
                store=ProfileStore([]),
                discovery=AssetDiscovery([]),
            )
            device = UsbDeviceInfo(1, 2, 0x0E8D, 0x0003, DeviceMode.BROM)
            result = session.run(device)
            session.close()
        self.assertTrue(result.da1_uploaded)
        self.assertTrue(result.da2_booted)
        self.assertEqual(result.protocol, "xml")
        self.assertEqual(session.brom.sent_da, [(0x40000000, 0x100, 0x10)])
        self.assertEqual(session.brom.jumped, [0x40000000])
        written = bytes(transport.writes)
        self.assertIn(b"CMD:SET-RUNTIME-PARAMETER", written)
        self.assertIn(b"CMD:BOOT-TO", written)
        self.assertIn(b"CMD:HOST-SUPPORTED-COMMANDS", written)
        self.assertIn(b"CMD:NOTIFY-INIT-HW", written)

    def test_unreadable_auth_bundle_is_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            da = root / "MTK_DA_V6.bin"
            da.write_bytes(build_da())
            session = ScriptedSession(
                FakeTransport(),
                options=AppOptions(da=da, auth=root / "missing.auth"),
                store=ProfileStore([]),
                discovery=AssetDiscovery([]),
            )
            device = UsbDeviceInfo(1, 2, 0x0E8D, 0x0003, DeviceMode.BROM)
            with self.assertRaises(AuthError):
                session.run(device)
            session.close()


if __name__ == "__main__":
    unittest.main()
