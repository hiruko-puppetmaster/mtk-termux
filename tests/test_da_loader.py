from __future__ import annotations

import struct
import unittest

from core.da_loader import DaLoader, DaRegion, extract_emi


def build_da() -> bytes:
    data = bytearray(0x800)
    data[0x10:0x10 + len(b"MTK_DA_v6")] = b"MTK_DA_v6"
    struct.pack_into("<I", data, 0x68, 1)  # one entry
    base = 0x6C
    struct.pack_into(
        "<HHHHHHHHHH",
        data,
        base,
        0x1234,  # magic
        0x0766,  # hw code
        0x8A00,  # sub code
        0x0001,  # hw version
        0x0002,  # sw version
        0,
        0x200,
        0,
        1,
        3,
    )
    regions = [
        (0x300, 0x40, 0x30000000, 0x40, 0),
        (0x400, 0x100, 0x40000000, 0x100, 0x10),
        (0x500, 0x80, 0x40100000, 0x80, 0x10),
    ]
    pos = base + 20
    for region in regions:
        struct.pack_into("<IIIII", data, pos, *region)
        pos += 20
    data[0x300:0x340] = b"A" * 0x40
    data[0x400:0x500] = b"B" * 0x100
    data[0x500:0x580] = b"C" * 0x80
    return bytes(data)


def build_old_da() -> bytes:
    """Build a legacy (0xD8-stride) DA entry without sw_version."""

    data = bytearray(0x800)
    struct.pack_into("<I", data, 0x68, 1)
    base = 0x6C
    struct.pack_into(
        "<HHHHHHHH",
        data,
        base,
        0x1234,  # magic
        0x0766,  # hw code
        0x8A00,  # sub code
        0x0001,  # hw version
        0x0200,  # pagesize (follows hw_version in old entries)
        0,
        1,
        3,
    )
    regions = [
        (0x300, 0x40, 0x30000000, 0x40, 0),
        (0x400, 0x100, 0x40000000, 0x100, 0x10),
        (0x500, 0x80, 0x40100000, 0x80, 0x10),
    ]
    pos = base + 16
    for region in regions:
        struct.pack_into("<IIIII", data, pos, *region)
        pos += 20
    data[base + 0xD8 : base + 0xD8 + 2] = b"\xDA\xDA"
    data[0x300:0x340] = b"A" * 0x40
    data[0x400:0x500] = b"B" * 0x100
    data[0x500:0x580] = b"C" * 0x80
    return bytes(data)


class DaLoaderTests(unittest.TestCase):
    def test_parse_and_select(self):
        loader = DaLoader.from_bytes(build_da(), "fake.bin")
        self.assertTrue(loader.v6)
        self.assertEqual(len(loader.entries), 1)
        entry = loader.select(0x0766, hw_version=1, sw_version=2)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.hw_sub_code, 0x8A00)
        self.assertEqual(loader.da1_bytes(entry), b"B" * 0x100)
        self.assertEqual(loader.da2_bytes(entry), b"C" * 0x80)
        self.assertEqual(entry.da1.address, 0x40000000)
        self.assertEqual(entry.da2.address, 0x40100000)

    def test_no_match(self):
        loader = DaLoader.from_bytes(build_da())
        self.assertIsNone(loader.select(0x9999))

    def test_newer_loader_revision_is_rejected(self):
        loader = DaLoader.from_bytes(build_da())
        # Zero means "unknown", so it must not filter anything.
        self.assertIsNotNone(loader.select(0x0766, hw_version=0))
        self.assertIsNotNone(loader.select(0x0766, hw_version=1))
        self.assertIsNone(loader.select(0x0766, hw_version=1, sw_version=1))

    def test_old_loader_layout(self):
        loader = DaLoader.from_bytes(build_old_da(), "old.bin")
        self.assertFalse(loader.v6)
        entry = loader.entries[0]
        self.assertTrue(entry.old_loader)
        self.assertEqual(entry.pagesize, 0x200)
        self.assertEqual(entry.sw_version, 0)
        self.assertEqual(entry.entry_region_count, 3)
        self.assertEqual(loader.da1_bytes(entry), b"B" * 0x100)
        self.assertEqual(loader.da2_bytes(entry), b"C" * 0x80)

    def test_region_validation(self):
        with self.assertRaises(Exception):
            DaRegion(0, 10, 0, 0, 11)

    def test_preloader_emi_not_required(self):
        image = extract_emi(b"\x00" * 16 + b"MTK_BLOADER_INFO_v12\x00" + b"\x00" * 32)
        self.assertEqual(image.version, 12)
        self.assertIsNone(image.emi)

    def test_small_xflash_preloader_is_emi(self):
        data = b"MTK_BLOADER_INFO_v35\x00" + b"\x00" * 0x60 + b"MTK_BIN" + b"\x00" * 0x20
        image = extract_emi(data)
        self.assertEqual(image.version, 35)
        self.assertEqual(image.emi, data)

    def test_mmm_preloader_extracts_emi_region(self):
        emi_payload = b"E" * 0x20
        region = b"PFX!" + b"MTK_BIN" + b"H" * 0xC + emi_payload
        dramsize = len(region)
        blob = bytearray(0x30)
        blob[0:8] = b"MMM\x01\x38\x00\x00\x00"
        body_length = len(blob) + len(region) + 4
        struct.pack_into("<I", blob, 0x20, body_length)
        struct.pack_into("<I", blob, 0x2C, 0)
        body = bytes(blob) + region + struct.pack("<I", dramsize)
        data = b"PRE" + b"MTK_BLOADER_INFO_v12\x00" + b"\x00" * 8 + body
        image = extract_emi(data)
        self.assertEqual(image.version, 12)
        self.assertEqual(image.dramsize, dramsize)
        self.assertIsNotNone(image.emi)
        self.assertTrue(image.emi.endswith(emi_payload))
        self.assertNotIn(b"MTK_BIN", image.emi[:8])


if __name__ == "__main__":
    unittest.main()
