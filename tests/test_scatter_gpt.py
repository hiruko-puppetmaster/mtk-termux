from __future__ import annotations

import struct
import unittest
import uuid
import zlib

from core.errors import ParserError
from parsers.scatter_gpt import (
    GptTable,
    parse_gpt,
    parse_scatter,
    read_gpt,
)

SCATTER = """
# sample scatter
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.1
      platform: MT6765
      project: demo
- partition_index: SYS0
  partition_name: preloader
  file_name: preloader.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x40000
  region: EMMC_BOOT_1
  storage: HW_STORAGE_EMMC
- partition_index: SYS1
  partition_name: boot
  file_name: boot.img
  linear_start_addr: 0x40000
  physical_start_addr: 0x40000
  partition_size: 0x2000000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
- partition_index: SYS2
  partition_name: userdata
  linear_start_addr: 0x2040000
  physical_start_addr: 0x2040000
  partition_size: 0x10000000
"""


def make_gpt(sector_size: int = 512, entries_lba: int = 2) -> tuple[bytes, GptTable]:
    entry_size = 128
    count = 4
    entries = bytearray(entry_size * count)
    parts = [
        ("boot", 2048, 4095),
        ("userdata", 4096, 8191),
    ]
    for index, (name, first, last) in enumerate(parts):
        raw = bytearray(entry_size)
        type_guid = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
        unique = uuid.UUID(f"12345678-1234-5678-1234-{index:012d}")
        raw[0:16] = type_guid.bytes_le
        raw[16:32] = unique.bytes_le
        struct.pack_into("<QQQ", raw, 32, first, last, 0)
        name_utf16 = name.encode("utf-16-le")[0:72]
        raw[56:56 + len(name_utf16)] = name_utf16
        entries[index * entry_size : (index + 1) * entry_size] = raw
    entries_crc = zlib.crc32(entries) & 0xFFFFFFFF
    header = bytearray(sector_size)
    header[0:8] = b"EFI PART"
    struct.pack_into("<IIII", header, 8, 0x00010000, 92, 0, 0)
    struct.pack_into("<QQQQ", header, 24, 1, 100, 34, 99)
    header[56:72] = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes_le
    struct.pack_into("<QIII", header, 72, entries_lba, count, entry_size, entries_crc)
    header_crc = zlib.crc32(header[:92]) & 0xFFFFFFFF
    struct.pack_into("<I", header, 16, header_crc)

    mbr = bytearray(sector_size)
    mbr[510:512] = b"\x55\xaa"
    mbr[446 + 4] = 0xEE
    struct.pack_into("<II", mbr, 446 + 8, 1, 100)
    padding = b"\x00" * (sector_size * max(0, entries_lba - 2))
    data = (
        bytes(mbr)
        + bytes(header)
        + padding
        + bytes(entries)
        + b"\x00" * (sector_size * 4)
    )
    return data, parse_gpt(data, sector_size=sector_size)


class ScatterTests(unittest.TestCase):
    def test_parse_scatter(self):
        scatter = parse_scatter(SCATTER)
        self.assertEqual(scatter.platform, "MT6765")
        self.assertEqual(len(scatter.partitions), 3)
        self.assertEqual(scatter.get("boot").start, 0x40000)
        self.assertEqual(scatter.get("userdata").size, 0x10000000)
        self.assertEqual(scatter.get("preloader").region, "EMMC_BOOT_1")

    def test_overlap(self):
        text = SCATTER.replace(
            "physical_start_addr: 0x2040000", "physical_start_addr: 0x1000000"
        )
        with self.assertRaises(ParserError):
            parse_scatter(text)

    def test_same_offset_in_different_regions_is_allowed(self):
        text = SCATTER + """
- partition_index: SYS3
  partition_name: pgpt
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x40000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
"""
        scatter = parse_scatter(text)
        self.assertEqual(scatter.get("pgpt").start, 0)
        self.assertEqual(scatter.get("preloader").start, 0)

    def test_scatter_xml_tags_are_case_insensitive(self):
        xml = """<?xml version="1.0"?>
<Partitions>
  <Partition>
    <PARTITION_NAME>boot</PARTITION_NAME>
    <Physical_Start_Addr>0x1000</Physical_Start_Addr>
    <Partition_Size>0x2000</Partition_Size>
  </Partition>
</Partitions>"""
        scatter = parse_scatter(xml)
        self.assertEqual(scatter.get("boot").start, 0x1000)
        self.assertEqual(scatter.get("boot").size, 0x2000)


class GptTests(unittest.TestCase):
    def test_parse_gpt(self):
        data, table = make_gpt()
        self.assertEqual(table.disk_guid, uuid.UUID("11111111-2222-3333-4444-555555555555"))
        self.assertEqual(len(table.partitions), 2)
        boot = table.get("boot")
        self.assertIsNotNone(boot)
        self.assertEqual(boot.start, 2048 * 512)
        self.assertEqual(boot.size, 2048 * 512)

    def test_crc_failure(self):
        data, _ = make_gpt()
        broken = bytearray(data)
        broken[512 + 20] ^= 0xFF
        with self.assertRaises(ParserError):
            parse_gpt(bytes(broken))

    def test_crc_checks_can_be_disabled(self):
        data, table = make_gpt()
        broken = bytearray(data)
        # Corrupt both the header CRC field and an entry byte.
        broken[512 + 20] ^= 0xFF
        broken[512 + 512 + 32] ^= 0xFF
        recovered = parse_gpt(bytes(broken), validate_crc=False)
        self.assertEqual(recovered.disk_guid, table.disk_guid)
        self.assertEqual(len(recovered.partitions), 2)

    def test_read_gpt_stream(self):
        import io

        data, table = make_gpt()
        stream = io.BytesIO(data)
        parsed = read_gpt(stream)
        self.assertEqual(len(parsed.partitions), 2)
        self.assertEqual(parsed.get("userdata").first_lba, 4096)

    def test_read_gpt_stream_entries_lba(self):
        import io

        data, _ = make_gpt(entries_lba=8)
        parsed = read_gpt(io.BytesIO(data))
        self.assertEqual(parsed.entries_lba, 8)
        self.assertEqual(len(parsed.partitions), 2)
        self.assertEqual(parsed.get("boot").start, 2048 * 512)

    def test_to_scatter(self):
        _, table = make_gpt()
        scatter = table.to_scatter()
        self.assertEqual(scatter.get("boot").start, 2048 * 512)

    def test_parse_raw_header_and_entries(self):
        data, table = make_gpt()
        # Drop the protective MBR so the buffer starts at the GPT header.
        raw = data[512:]
        parsed = parse_gpt(raw)
        self.assertEqual(parsed.disk_guid, table.disk_guid)
        self.assertEqual(len(parsed.partitions), 2)
        self.assertEqual(parsed.get("boot").first_lba, 2048)

    def test_implausible_entry_size_is_rejected(self):
        data, _ = make_gpt()
        broken = bytearray(data)
        struct.pack_into("<I", broken, 512 + 84, 0x10000)
        header = bytearray(broken[512 : 512 + 92])
        struct.pack_into("<I", header, 16, 0)
        struct.pack_into(
            "<I", broken, 512 + 16, zlib.crc32(header) & 0xFFFFFFFF
        )
        with self.assertRaises(ParserError):
            parse_gpt(bytes(broken))


if __name__ == "__main__":
    unittest.main()
