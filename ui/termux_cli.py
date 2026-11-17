"""Command-line entry point.

Examples:
  python -m ui.termux_cli --mode scan
  python -m ui.termux_cli --mode probe --wait 30
  python -m ui.termux_cli --mode manual --da MTK_AllInOne_DA.bin \
      --preloader preloader.bin --auth device.auth
  python -m ui.termux_cli --mode auto --once --profiles-dir ./profiles

Nothing is flashed by default.  The session stops after DA2 starts; flashing
operations are intentionally exposed as library APIs so a caller must opt in
with explicit partition/address arguments.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Sequence

from core.errors import MtkError, PermissionDenied
from core.options import AppOptions
from core.profiles import AssetDiscovery, ProfileStore
from core.session import DeviceSession
from termux_transport.usb_host import (
    DeviceMode,
    UsbHost,
    check_root,
    elevate,
    require_root,
    root_diagnostics,
)

VERSION = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mtk-termux",
        description=(
            "MediaTek BROM/Preloader servicing toolkit for rooted Termux or "
            "Linux.  The default mode is the interactive TUI."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Termux setup:\n"
            "  pkg install python libusb clang make git\n"
            "  python -m pip install pyusb rich\n"
            "  su -c 'python -m ui.termux_cli --mode auto'\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument(
        "--mode",
        choices=["tui", "auto", "manual", "scan", "probe", "validate"],
        default="tui",
        help="operation mode (default: tui)",
    )
    parser.add_argument("--da", type=Path, help="Download Agent container (MTK_AllInOne_DA.bin)")
    parser.add_argument("--preloader", type=Path, help="preloader/EMI image")
    parser.add_argument("--auth", type=Path, help=".auth bundle for SLA/DAA")
    parser.add_argument("--payload", type=Path, help="exploit payload blob")
    parser.add_argument(
        "--profiles-dir",
        type=Path,
        help="directory containing SoC profile JSON files",
    )
    parser.add_argument(
        "--assets-dir",
        type=Path,
        action="append",
        default=[],
        help="additional directory to scan for DA/preloader/auth files (repeatable)",
    )
    parser.add_argument(
        "--exploit",
        choices=["auto", "kamakiri", "heapb8", "none"],
        default="auto",
        help="exploit strategy (default: auto from profile)",
    )
    parser.add_argument("--once", action="store_true", help="auto/probe: stop after one device")
    parser.add_argument(
        "--wait",
        type=float,
        default=0.0,
        metavar="SECONDS",
        help="wait this long for a device (0 = forever)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate files and profiles without opening USB",
    )
    parser.add_argument(
        "--allow-unsigned-da",
        action="store_true",
        help="continue after an auth failure (for development devices only)",
    )
    parser.add_argument(
        "--no-root-check",
        action="store_true",
        help="skip the uid-0 pre-check and rely on the actual usbfs permissions",
    )
    parser.add_argument("--elevate", action="store_true", help="re-exec through su -c")
    parser.add_argument("--json", action="store_true", help="JSON output where applicable")
    parser.add_argument("--no-color", action="store_true", help="disable Rich colors")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="print loaded SoC profiles and exit",
    )
    return parser


def options_from_args(args: argparse.Namespace) -> AppOptions:
    return AppOptions(
        mode=args.mode,
        da=args.da,
        preloader=args.preloader,
        auth=args.auth,
        payload=args.payload,
        profiles_dir=args.profiles_dir,
        exploit=args.exploit,
        once=args.once,
        wait_timeout=args.wait,
        dry_run=args.dry_run,
        allow_unsigned_da=args.allow_unsigned_da,
        no_root_check=args.no_root_check,
        json=args.json,
        verbose=args.verbose,
        no_color=args.no_color,
        elevate=args.elevate,
        extra_asset_dirs=list(args.assets_dir),
    )


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _print_devices(devices, as_json: bool) -> None:
    if as_json:
        print(json.dumps([
            {
                "bus": d.bus,
                "address": d.address,
                "vendor_id": f"0x{d.vendor_id:04x}",
                "product_id": f"0x{d.product_id:04x}",
                "mode": d.mode.value,
                "path": str(d.dev_path),
                "manufacturer": d.manufacturer,
                "product": d.product,
            }
            for d in devices
        ], indent=2))
        return
    if not devices:
        print("No USB devices found.")
        return
    print(f"{'MODE':<10} {'VID:PID':<10} {'BUS/ADDR':<10} PATH")
    for d in devices:
        print(
            f"{d.mode.value:<10} {d.vendor_id:04x}:{d.product_id:04x} "
            f"{d.bus:03d}/{d.address:03d}   {d.dev_path}"
        )


def _print_profiles(store: ProfileStore) -> None:
    if not store.profiles:
        print("No profiles loaded. Add JSON files under ./profiles or --profiles-dir.")
    for profile in store.profiles:
        print(
            f"0x{profile.hw_code:04X}  {profile.name:<18} "
            f"exploit={profile.exploit:<8} da={profile.da or '—'}"
        )
    for error in store.errors:
        print(f"profile error: {error}")


def _run_headless(options: AppOptions) -> int:
    host = UsbHost()
    store = ProfileStore([options.profiles_dir] if options.profiles_dir else None)
    discovery = AssetDiscovery(options.extra_asset_dirs)
    if not options.no_root_check:
        require_root(probe_su=True)
    if options.mode == "probe":
        device = host.wait_for_device(timeout=options.wait_timeout)
        if device is None:
            print("No BROM/Preloader device detected.", file=sys.stderr)
            return 1
        with DeviceSession(options, host=host, store=store, discovery=discovery) as session:
            result = session.probe(device)
        print(f"HW_CODE: {result.hw_code}")
        print(f"target:  0x{result.target_config.raw:08X}")
        print(
            "SBC: {} SLA: {} DAA: {}".format(
                result.target_config.sbc,
                result.target_config.sla,
                result.target_config.daa,
            )
        )
        return 0

    handled = 0
    while True:
        device = host.wait_for_device(timeout=options.wait_timeout)
        if device is None:
            print("No BROM/Preloader device detected.", file=sys.stderr)
            return 1 if not handled else 0
        with DeviceSession(options, host=host, store=store, discovery=discovery) as session:
            result = session.run(device)
        print(f"HW_CODE: {result.hw_code}")
        print(f"DA:      {result.da_path}")
        print(f"protocol:{result.protocol}")
        print(f"DA1:     {result.da1_uploaded}")
        print(f"DA2:     {result.da2_booted}")
        if result.exploit:
            print(f"exploit: {result.exploit.name}")
        handled += 1
        if options.once or options.mode != "auto":
            return 0
        # Wait for the target to leave so a reset does not replay immediately.
        while host.find() is not None:
            import time

            time.sleep(0.25)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    options = options_from_args(args)

    if args.elevate and not check_root(probe_su=False):
        forwarded = list(argv if argv is not None else sys.argv[1:])
        elevate([sys.executable, "-m", "ui.termux_cli", *forwarded])
        return 0

    if args.list_profiles:
        _print_profiles(ProfileStore([options.profiles_dir] if options.profiles_dir else None))
        return 0

    if args.mode == "validate" or args.dry_run:
        try:
            messages = DeviceSession.validate_only(options)
        except (MtkError, OSError, ValueError) as exc:
            print(f"validation failed: {exc}", file=sys.stderr)
            return 1
        print("Validation OK")
        for message in messages:
            print(f"  {message}")
        return 0

    if args.mode == "scan":
        devices = UsbHost().scan()
        _print_devices(devices, args.json)
        return 0

    diag = root_diagnostics()
    if not diag["is_root"] and not args.no_root_check:
        # The TUI can still show diagnostics and scan; only device-opening
        # operations need root.  Let the TUI guide the user.
        if args.mode != "tui":
            print("Root is required to open /dev/bus/usb.", file=sys.stderr)
            print(f"diagnostics: {diag}", file=sys.stderr)
            print(
                "Re-run with: su -c 'python -m ui.termux_cli ...' "
                "or pass --elevate",
                file=sys.stderr,
            )
            return 2

    if args.mode == "tui":
        try:
            from ui.terminal_tui import run_tui

            return run_tui(options)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    try:
        return _run_headless(options)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except PermissionDenied as exc:
        print(f"permission denied: {exc}", file=sys.stderr)
        return 2
    except MtkError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
