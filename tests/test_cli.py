from __future__ import annotations

import unittest

from ui.termux_cli import build_parser, options_from_args


class CliTests(unittest.TestCase):
    def test_manual_arguments(self):
        args = build_parser().parse_args(
            [
                "--mode",
                "manual",
                "--da",
                "DA.bin",
                "--preloader",
                "preloader.bin",
                "--auth",
                "device.auth",
                "--no-color",
            ]
        )
        options = options_from_args(args)
        self.assertEqual(options.mode, "manual")
        self.assertEqual(str(options.da), "DA.bin")
        self.assertTrue(options.no_color)

    def test_auto_once(self):
        args = build_parser().parse_args(["--mode", "auto", "--once", "--exploit", "kamakiri"])
        options = options_from_args(args)
        self.assertTrue(options.once)
        self.assertEqual(options.exploit, "kamakiri")


if __name__ == "__main__":
    unittest.main()
