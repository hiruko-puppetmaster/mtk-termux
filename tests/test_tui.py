from __future__ import annotations

import io
import unittest

from core.options import AppOptions
from termux_transport.usb_host import DeviceMode, UsbDeviceInfo

try:
    from rich.console import Console

    from ui.terminal_tui import TerminalTUI

    HAVE_RICH = True
except ImportError:  # pragma: no cover - rich is optional
    HAVE_RICH = False


@unittest.skipUnless(HAVE_RICH, "rich is not installed")
class TuiRenderingTests(unittest.TestCase):
    def _tui(self) -> tuple[TerminalTUI, io.StringIO]:
        stream = io.StringIO()
        console = Console(
            file=stream, width=120, no_color=True, highlight=False, soft_wrap=True
        )
        return TerminalTUI(AppOptions(no_color=True), console=console), stream

    def test_device_table(self):
        tui, stream = self._tui()
        table = tui.device_table(
            [
                UsbDeviceInfo(
                    1, 7, 0x0E8D, 0x0003, DeviceMode.BROM, product="BROM"
                )
            ]
        )
        tui.console.print(table)
        output = stream.getvalue()
        self.assertIn("0e8d:0003", output)
        self.assertIn("brom", output)

    def test_empty_device_table(self):
        tui, stream = self._tui()
        tui.console.print(tui.device_table([]))
        self.assertIn("no matching MediaTek device", stream.getvalue())

    def test_scan_without_devices(self):
        tui, stream = self._tui()
        devices = tui.scan()
        self.assertEqual(devices, [])
        self.assertIn("USB devices", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
