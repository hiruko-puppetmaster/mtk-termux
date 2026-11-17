from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from termux_transport.usb_host import (
    BROM_PID,
    MTK_VID,
    PRELOADER_PID,
    ClaimedUsbDevice,
    DeviceMode,
    UsbDeviceInfo,
    enumerate_sysfs,
)


class _FakeEndpoint:
    def __init__(self) -> None:
        self.calls: list[tuple[bytes, int]] = []

    def write(self, data: bytes, timeout: int) -> int:
        self.calls.append((bytes(data), timeout))
        return len(data)


class UsbTests(unittest.TestCase):
    def test_device_mode(self):
        self.assertIs(DeviceMode.from_ids(MTK_VID, BROM_PID), DeviceMode.BROM)
        self.assertIs(DeviceMode.from_ids(MTK_VID, PRELOADER_PID), DeviceMode.PRELOADER)
        self.assertIs(DeviceMode.from_ids(0x1234, 0x5678), DeviceMode.OTHER)

    def test_sysfs_enumeration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = root / "1-1"
            entry.mkdir()
            (entry / "idVendor").write_text("0e8d\n")
            (entry / "idProduct").write_text("0003\n")
            (entry / "busnum").write_text("1\n")
            (entry / "devnum").write_text("7\n")
            (entry / "product").write_text("MTK BROM\n")
            devices = enumerate_sysfs(root)
            self.assertEqual(len(devices), 1)
            self.assertEqual(devices[0].mode, DeviceMode.BROM)
            self.assertEqual(devices[0].dev_path, Path("/dev/bus/usb/001/007"))

    def test_invalid_sysfs_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "nope").mkdir()
            self.assertEqual(enumerate_sysfs(root), [])

    def test_path_format(self):
        info = UsbDeviceInfo(1, 2, MTK_VID, BROM_PID, DeviceMode.BROM)
        self.assertTrue(str(info.dev_path).endswith("/001/002"))

    def test_zero_length_write_reaches_usb_endpoint(self):
        transport = object.__new__(ClaimedUsbDevice)
        transport.ep_out = _FakeEndpoint()
        transport.timeout_ms = 750
        self.assertEqual(transport.write(b""), 0)
        self.assertEqual(transport.ep_out.calls, [(b"", 750)])


if __name__ == "__main__":
    unittest.main()
