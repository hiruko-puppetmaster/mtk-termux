"""Rich terminal UI with explicit manual and automatic servicing modes."""

from __future__ import annotations

import logging
import signal
import time
from pathlib import Path
from typing import Iterable

from core.errors import MtkError, PermissionDenied
from core.options import AppOptions, null_progress
from core.profiles import AssetDiscovery, ProfileStore
from core.session import DeviceSession, ProbeResult, SessionResult
from termux_transport.usb_host import (
    DeviceMode,
    HotplugPoller,
    UsbDeviceInfo,
    UsbHost,
    check_root,
    root_diagnostics,
)

try:  # Rich is optional so scan/manual CLI still works without it.
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.prompt import Prompt
    from rich.table import Table
    from rich.text import Text

    _RICH = True
except ImportError:  # pragma: no cover - depends on host environment
    Console = object  # type: ignore
    _RICH = False

LOG = logging.getLogger("mtk.tui")


def _require_rich() -> None:
    if not _RICH:
        raise RuntimeError(
            "The interactive TUI needs rich. Install it with:\n"
            "  python -m pip install rich\n"
            "or run the non-interactive commands: --mode scan / --mode auto / "
            "--mode manual with explicit paths."
        )


class TerminalTUI:
    def __init__(self, options: AppOptions, console: "Console | None" = None) -> None:
        _require_rich()
        self.options = options
        self.console = console or Console(
            no_color=options.no_color, highlight=False, soft_wrap=True
        )
        self.host = UsbHost()
        self.store = ProfileStore(
            [options.profiles_dir] if options.profiles_dir else None
        )
        self.discovery = AssetDiscovery(options.extra_asset_dirs)
        self._stop = False

    # ---- presentation ---------------------------------------------------
    def banner(self) -> None:
        self.console.print(
            Panel.fit(
                "[bold cyan]mtk-termux[/bold cyan]  "
                "[dim]MediaTek BROM / DA servicing[/dim]\n"
                "[dim]rooted Termux · OTG · BROM/Preloader · XFlash V5 · DA v6 XML[/dim]",
                border_style="cyan",
            )
        )
        diag = root_diagnostics()
        root_text = "[green]root[/green]" if diag["is_root"] else (
            "[yellow]su available[/yellow]" if diag["su_available"] else "[red]not root[/red]"
        )
        self.console.print(
            f"  uid={diag['euid']}  {root_text}  "
            f"selinux={'enforcing' if diag['selinux_enforcing'] else 'permissive/unknown'}  "
            f"usbfs={'present' if diag['dev_bus_usb'] else 'missing'}"
        )
        if not diag["is_root"] and not diag["su_available"]:
            self.console.print(
                "[yellow]Tip:[/yellow] /dev/bus/usb needs uid 0. Use Magisk/KernelSU "
                "and run via [bold]su -c[/bold]."
            )
        if self.store.errors:
            for error in self.store.errors:
                self.console.print(f"[yellow]profile warning:[/yellow] {error}")

    def device_table(self, devices: Iterable[UsbDeviceInfo]) -> "Table":
        table = Table(title="USB devices", show_header=True, header_style="bold cyan")
        table.add_column("Mode", style="magenta", no_wrap=True)
        table.add_column("VID:PID")
        table.add_column("Bus/Addr")
        table.add_column("Path")
        table.add_column("Product")
        rows = 0
        for device in devices:
            rows += 1
            style = "green" if device.mode is not DeviceMode.OTHER else "dim"
            table.add_row(
                Text(device.mode.value, style=style),
                f"{device.vendor_id:04x}:{device.product_id:04x}",
                f"{device.bus:03d}/{device.address:03d}",
                str(device.dev_path),
                device.product or device.manufacturer or "",
            )
        if not rows:
            table.add_row("—", "—", "—", "—", "no matching MediaTek device")
        return table

    def result_panel(self, result: SessionResult | ProbeResult) -> "Panel":
        if isinstance(result, ProbeResult):
            body = (
                f"[bold]HW_CODE[/bold] {result.hw_code}\n"
                f"[bold]target[/bold] 0x{result.target_config.raw:08X}\n"
                f"[bold]SBC/SLA/DAA[/bold] "
                f"{result.target_config.sbc}/{result.target_config.sla}/{result.target_config.daa}\n"
                f"[bold]BROM[/bold] {result.brom_version if result.brom_version is not None else 'unknown'}"
            )
            return Panel(body, title="probe", border_style="green")
        lines = [
            f"[bold]device[/bold] {result.device.label}",
            f"[bold]HW_CODE[/bold] {result.hw_code}",
            f"[bold]target[/bold] 0x{result.target_config.raw:08X} "
            f"(SBC={result.target_config.sbc}, SLA={result.target_config.sla}, "
            f"DAA={result.target_config.daa})",
            f"[bold]DA[/bold] {result.da_path or '—'}",
            f"[bold]preloader[/bold] {result.preloader_path or '—'}",
            f"[bold]auth[/bold] {result.auth_path or '—'}",
            f"[bold]exploit[/bold] {result.exploit.name if result.exploit else 'none'}",
            f"[bold]DA1/DA2[/bold] {result.da1_uploaded}/{result.da2_booted} "
            f"({result.protocol or '—'})",
        ]
        if result.notes:
            lines.append("[bold]notes[/bold] " + "; ".join(result.notes))
        return Panel("\n".join(lines), title="session", border_style="green")

    # ---- top-level modes ------------------------------------------------
    def run(self) -> int:
        self.banner()
        mode = self.options.mode
        if mode == "auto":
            return self.auto()
        if mode == "manual":
            return self.manual()
        return self.menu()

    def menu(self) -> int:
        while not self._stop:
            self.console.print()
            self.console.print("[bold]Select a mode[/bold]")
            self.console.print("  [cyan]1[/cyan] Automatic  — poll OTG and service the next BROM/Preloader device")
            self.console.print("  [cyan]2[/cyan] Manual     — choose DA, preloader and auth, then arm")
            self.console.print("  [cyan]3[/cyan] Scan       — show USB devices")
            self.console.print("  [cyan]4[/cyan] Probe      — handshake and read HW_CODE")
            self.console.print("  [cyan]q[/cyan] Quit")
            choice = Prompt.ask("Mode", choices=["1", "2", "3", "4", "q"], default="1")
            if choice == "q":
                return 0
            if choice == "1":
                return self.auto()
            if choice == "2":
                return self.manual()
            if choice == "3":
                self.scan()
            if choice == "4":
                self.probe_interactive()
        return 0

    def scan(self) -> list[UsbDeviceInfo]:
        devices = self.host.scan()
        self.console.print(self.device_table(devices))
        if self.options.json:
            import json

            self.console.print_json(json.dumps([
                {
                    "bus": d.bus,
                    "address": d.address,
                    "vendor_id": f"0x{d.vendor_id:04x}",
                    "product_id": f"0x{d.product_id:04x}",
                    "mode": d.mode.value,
                    "path": str(d.dev_path),
                }
                for d in devices
            ]))
        return devices

    def probe_interactive(self) -> int:
        device = self.host.wait_for_device(timeout=self.options.wait_timeout)
        if device is None:
            self.console.print("[yellow]No MediaTek BROM/Preloader device found.[/yellow]")
            return 1
        try:
            with self._progress() as progress:
                with DeviceSession(
                    self.options,
                    host=self.host,
                    store=self.store,
                    discovery=self.discovery,
                    progress=self._progress_callback(progress),
                ) as session:
                    result = session.probe(device)
                progress.update(progress.task_ids[0], completed=100)
            self.console.print(self.result_panel(result))
            return 0
        except (MtkError, PermissionError, OSError) as exc:
            self.console.print(f"[red]probe failed:[/red] {exc}")
            return 1

    # ---- manual ---------------------------------------------------------
    def manual(self) -> int:
        self.console.print("\n[bold cyan]Manual mode[/bold cyan]")
        da = self.options.da or self._choose_asset(
            "Download Agent (DA)", self.discovery.da_candidates(), required=True
        )
        preloader = self.options.preloader or self._choose_asset(
            "Preloader (EMI/DRAM calibration)",
            self.discovery.preloader_candidates(),
            required=False,
        )
        auth = self.options.auth or self._choose_asset(
            "Auth bundle (.auth, optional)", self.discovery.auth_candidates(), required=False
        )
        payload = self.options.payload
        if self.options.exploit in ("kamakiri", "heapb8") and payload is None:
            payload = self._choose_asset(
                "Exploit payload", self.discovery.files(("*.bin",)), required=True
            )
        self.options.da = da
        self.options.preloader = preloader
        self.options.auth = auth
        self.options.payload = payload
        self.console.print(
            Panel(
                f"DA:        {da}\n"
                f"Preloader: {preloader or '—'}\n"
                f"Auth:      {auth or '—'}\n"
                f"Payload:   {payload or '—'}\n"
                f"Exploit:   {self.options.exploit}",
                title="manual assets",
                border_style="cyan",
            )
        )
        Prompt.ask("Press Enter to arm the USB trigger", default="", show_default=False)
        device = self.host.wait_for_device(timeout=self.options.wait_timeout)
        if device is None:
            self.console.print("[yellow]No device appeared before the wait timeout.[/yellow]")
            return 1
        return self._run_device(device)

    def _choose_asset(self, label: str, candidates: list[Path], required: bool) -> Path | None:
        if candidates:
            table = Table(title=f"{label} candidates", show_header=True, header_style="bold")
            table.add_column("#", justify="right", width=3)
            table.add_column("Path")
            for index, path in enumerate(candidates[:30], 1):
                table.add_row(str(index), str(path))
            self.console.print(table)
            prompt = f"{label} number or path"
        else:
            prompt = f"{label} path"
        while True:
            value = Prompt.ask(prompt, default="" if required else "", show_default=False)
            value = value.strip().strip("\"'")
            if not value:
                if not required:
                    return None
                self.console.print("[yellow]This field is required.[/yellow]")
                continue
            if value.isdigit() and candidates and 1 <= int(value) <= len(candidates):
                return candidates[int(value) - 1]
            path = Path(value).expanduser()
            if path.exists() and path.is_file():
                return path
            self.console.print(f"[red]Not a file:[/red] {path}")

    # ---- auto -----------------------------------------------------------
    def auto(self) -> int:
        self.console.print(
            "\n[bold cyan]Automatic mode[/bold cyan] — polling USB for "
            "[green]0e8d:0003[/green] (BROM) or [green]0e8d:2000[/green] (Preloader)"
        )
        self.console.print("[dim]Ctrl-C stops. Only one device is serviced per insertion.[/dim]")
        poller = HotplugPoller(self.host, mode=None, interval=0.15)
        last_rc = 0
        serviced = False
        for event, device in poller.poll(stop_event=self._stop_event()):
            if event != "add" or device.mode is DeviceMode.OTHER:
                continue
            self.console.print(f"\n[green]Detected[/green] {device.label}")
            last_rc = self._run_device(device)
            serviced = True
            if self.options.once or last_rc != 0:
                break
            # Wait for unplug before re-arming; avoids immediately replaying a
            # device that reset itself back into BROM.
            self.console.print("[dim]Waiting for unplug before re-arming…[/dim]")
            while self.host.find() is not None:
                time.sleep(0.25)
        return last_rc if serviced else 0

    def _stop_event(self):
        # Rich runs in the main thread; a KeyboardInterrupt already exits the
        # poller.  Return None so the poller is interruptible normally.
        return None

    # ---- pipeline and progress -----------------------------------------
    def _run_device(self, device: UsbDeviceInfo) -> int:
        try:
            with self._progress() as progress:
                with DeviceSession(
                    self.options,
                    host=self.host,
                    store=self.store,
                    discovery=self.discovery,
                    progress=self._progress_callback(progress),
                ) as session:
                    result = session.run(device)
                for task in progress.task_ids:
                    progress.update(task, completed=100)
            self.console.print(self.result_panel(result))
            return 0
        except KeyboardInterrupt:
            self.console.print("\n[yellow]interrupted[/yellow]")
            return 130
        except (MtkError, PermissionError, OSError) as exc:
            self.console.print(f"[red]session failed:[/red] {exc}")
            if not check_root(probe_su=False):
                self.console.print(
                    "[yellow]Run through su:[/yellow] [bold]su -c "
                    "'python -m ui.termux_cli --mode auto'[/bold]"
                )
            return 1

    def _progress(self):
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
        )

    def _progress_callback(self, progress):
        task = progress.add_task("waiting for device", total=100)

        def callback(stage: str, message: str, fraction: float | None = None) -> None:
            percent = None if fraction is None else max(0.0, min(1.0, fraction)) * 100
            progress.update(
                task,
                description=f"[cyan]{stage}[/cyan] {message}",
                completed=percent if percent is not None else progress.tasks[task].completed,
            )

        return callback


def run_tui(options: AppOptions) -> int:
    _require_rich()
    return TerminalTUI(options).run()


__all__ = ["TerminalTUI", "run_tui"]
