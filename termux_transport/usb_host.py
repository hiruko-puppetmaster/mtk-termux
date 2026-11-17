"""Low-level USB host access for rooted Termux and Linux.

The module deliberately keeps the kernel-facing details in one place:

* enumeration reads ``/sys/bus/usb/devices`` and optionally pyusb/libusb1;
* every device path is the Android/Linux usbfs path
  ``/dev/bus/usb/BBB/DDD``;
* opening a device validates root/permissions and uses the libusb1 backend;
* hotplug polling is a non-blocking sysfs scan, so the short BROM window
  (0x0e8d:0x0003) is not missed while a phone is plugged into an OTG cable.

No Android USB permission dialog can be answered by this process.  The tool is
for rooted devices (Magisk/KernelSU) or desktop Linux.  On an unrooted Termux
installation use ``termux-usb`` for a one-off file descriptor, or run the tool
through ``su -c`` after granting root.
"""

from __future__ import annotations

import ctypes.util
import errno
import os
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Sequence

from core.errors import PermissionDenied, TransportError

MTK_VID = 0x0E8D
BROM_PID = 0x0003
PRELOADER_PID = 0x2000
USBDEVFS_ROOT = Path("/dev/bus/usb")
SYSFS_USB_ROOT = Path("/sys/bus/usb/devices")

_BULK = 2
_INTERRUPT = 3


class DeviceMode(str, Enum):
    BROM = "brom"
    PRELOADER = "preloader"
    OTHER = "other"

    @classmethod
    def from_ids(cls, vendor_id: int, product_id: int) -> "DeviceMode":
        if vendor_id == MTK_VID and product_id == BROM_PID:
            return cls.BROM
        if vendor_id == MTK_VID and product_id == PRELOADER_PID:
            return cls.PRELOADER
        return cls.OTHER


@dataclass(frozen=True)
class UsbDeviceInfo:
    bus: int
    address: int
    vendor_id: int
    product_id: int
    mode: DeviceMode = DeviceMode.OTHER
    sysfs_path: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    serial: str | None = None

    @property
    def dev_path(self) -> Path:
        return USBDEVFS_ROOT / f"{self.bus:03d}" / f"{self.address:03d}"

    @property
    def key(self) -> tuple[int, int, int, int]:
        return (self.bus, self.address, self.vendor_id, self.product_id)

    @property
    def label(self) -> str:
        return (
            f"{self.vendor_id:04x}:{self.product_id:04x} "
            f"bus {self.bus:03d} addr {self.address:03d} ({self.mode.value})"
        )


def _read_text(path: Path, default: str = "") -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except (OSError, PermissionError):
        return default


def _read_int(path: Path, default: int = 0) -> int:
    try:
        return int(_read_text(path), 0)
    except (ValueError, TypeError):
        return default


def _read_hex(path: Path, default: int = -1) -> int:
    text = _read_text(path)
    if not text:
        return default
    try:
        return int(text, 16)
    except ValueError:
        return default


def enumerate_sysfs(root: Path = SYSFS_USB_ROOT) -> list[UsbDeviceInfo]:
    """Enumerate USB devices without opening a USB handle.

    This works when libusb cannot enumerate (common in minimal Termux images)
    and is also the source for the hotplug polling loop.
    """

    devices: list[UsbDeviceInfo] = []
    try:
        entries = list(root.iterdir())
    except (OSError, PermissionError):
        return devices

    for entry in entries:
        vendor = _read_hex(entry / "idVendor", -1)
        product = _read_hex(entry / "idProduct", -1)
        if vendor < 0 or product < 0:
            continue
        bus = _read_int(entry / "busnum", 0)
        address = _read_int(entry / "devnum", 0)
        if not bus or not address:
            continue
        devices.append(
            UsbDeviceInfo(
                bus=bus,
                address=address,
                vendor_id=vendor,
                product_id=product,
                mode=DeviceMode.from_ids(vendor, product),
                sysfs_path=str(entry),
                manufacturer=_read_text(entry / "manufacturer") or None,
                product=_read_text(entry / "product") or None,
                serial=_read_text(entry / "serial") or None,
            )
        )
    devices.sort(key=lambda d: (d.bus, d.address))
    return devices


def _find_libusb() -> str | None:
    """Find libusb-1.0 on Termux, Android and normal Linux distributions."""

    env = os.environ.get("MTK_LIBUSB")
    if env:
        return env
    candidates = []
    prefix = os.environ.get("PREFIX")
    if prefix:
        candidates.extend(
            [
                f"{prefix}/lib/libusb-1.0.so",
                f"{prefix}/lib/libusb-1.0.so.0",
            ]
        )
    candidates.extend(
        [
            "/data/data/com.termux/files/usr/lib/libusb-1.0.so",
            "/data/data/com.termux/files/usr/lib/libusb-1.0.so.0",
            "/system/lib64/libusb-1.0.so",
            "/system/lib/libusb-1.0.so",
            "/vendor/lib64/libusb-1.0.so",
            "/vendor/lib/libusb-1.0.so",
            "/usr/lib/x86_64-linux-gnu/libusb-1.0.so.0",
            "/usr/lib/aarch64-linux-gnu/libusb-1.0.so.0",
            "/usr/lib/libusb-1.0.so.0",
        ]
    )
    for item in candidates:
        if Path(item).exists():
            return item
    return ctypes.util.find_library("usb-1.0")


def _import_usb():
    try:
        import usb.core  # type: ignore
        import usb.util  # type: ignore
        import usb.backend.libusb1  # type: ignore
    except ImportError as exc:
        raise TransportError(
            "pyusb is not installed. Run: pkg install libusb python && "
            "python -m pip install pyusb"
        ) from exc
    return usb


def _libusb_backend():
    usb = _import_usb()
    lib = _find_libusb()
    try:
        backend = usb.backend.libusb1.get_backend(find_library=lambda _name: lib)
    except Exception as exc:  # pragma: no cover - platform dependent
        raise TransportError(f"Could not initialise libusb: {exc}") from exc
    if backend is None:
        raise TransportError(
            "libusb1 backend is unavailable. Install libusb (pkg install libusb) "
            "or set MTK_LIBUSB to the libusb-1.0 shared library."
        )
    return backend


def enumerate_pyusb() -> list[UsbDeviceInfo]:
    """Enumerate via pyusb, retaining bus/address for usbfs paths."""

    usb = _import_usb()
    backend = _libusb_backend()
    try:
        found = usb.core.find(find_all=True, backend=backend)
    except Exception as exc:
        raise TransportError(f"libusb enumeration failed: {exc}") from exc
    devices: list[UsbDeviceInfo] = []
    for dev in found or []:
        try:
            bus = int(dev.bus or 0)
            address = int(dev.address or 0)
            vendor = int(dev.idVendor)
            product = int(dev.idProduct)
            devices.append(
                UsbDeviceInfo(
                    bus=bus,
                    address=address,
                    vendor_id=vendor,
                    product_id=product,
                    mode=DeviceMode.from_ids(vendor, product),
                )
            )
        except Exception:
            continue
    devices.sort(key=lambda d: (d.bus, d.address))
    return devices


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _su_available() -> bool:
    return shutil.which("su") is not None


def _su_uid() -> int | None:
    if not _su_available():
        return None
    try:
        proc = subprocess.run(
            ["su", "-c", "id -u"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    try:
        return int(proc.stdout.decode("ascii", "replace").strip())
    except ValueError:
        return None


def check_root(probe_su: bool = True) -> bool:
    """Return true if the current process or ``su`` can be root."""

    if is_root():
        return True
    return bool(probe_su and _su_uid() == 0)


def root_diagnostics() -> dict[str, object]:
    selinux = Path("/sys/fs/selinux/enforce")
    enforce: bool | None = None
    if selinux.exists():
        enforce = _read_text(selinux) == "1"
    suid = _su_uid()
    return {
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "is_root": is_root(),
        "su_available": _su_available(),
        "su_uid": suid,
        "selinux_enforcing": enforce,
        "dev_bus_usb": USBDEVFS_ROOT.exists(),
        "termux": "com.termux" in os.environ.get("PREFIX", ""),
    }


def require_root(probe_su: bool = True) -> None:
    if check_root(probe_su=probe_su):
        return
    diag = root_diagnostics()
    hint = ""
    if diag["su_available"]:
        hint = (
            "\nsu is installed but did not return uid 0. Re-run through a root "
            "shell, for example:\n  su -c 'cd %s && python -m ui.termux_cli ...'"
            % os.getcwd()
        )
    else:
        hint = (
            "\nRoot is required because /dev/bus/usb is not readable by the "
            "Termux app. Use Magisk/KernelSU and run the command with su."
        )
    raise PermissionDenied(
        "This operation needs uid 0. Current diagnostics: "
        f"{diag}.{hint}"
    )


def elevate(argv: Sequence[str] | None = None, env: dict[str, str] | None = None) -> None:
    """Re-exec the current command through ``su -c`` (Linux/Termux).

    The function only returns if elevation is impossible.  A sentinel prevents
    accidental recursive elevation.
    """

    if is_root():
        return
    if os.environ.get("TERMUX_MTK_ELEVATED") == "1":
        raise PermissionDenied("Elevation was requested, but the process is still not root.")
    if shutil.which("su") is None:
        raise PermissionDenied("su was not found; install Magisk/KernelSU or run as root.")
    args = list(argv if argv is not None else sys.argv)
    cmd = " ".join(shlex.quote(a) for a in args)
    child_env = dict(os.environ if env is None else env)
    child_env["TERMUX_MTK_ELEVATED"] = "1"
    os.execvpe("su", ["su", "-c", cmd], child_env)


@dataclass
class _UsbFacade:
    """Tiny pyusb facade used by ClaimedUsbDevice."""

    dev: object
    usb: object


class ClaimedUsbDevice:
    """A USB device with a claimed interface and selected bulk endpoints.

    Implements the byte transport expected by ``core.protocols``.
    """

    def __init__(self, device: UsbDeviceInfo, timeout_ms: int = 1000) -> None:
        self.info = device
        self.timeout_ms = max(1, int(timeout_ms))
        self.usb = _import_usb()
        self.backend = _libusb_backend()
        self.dev = self._find(device)
        self.configuration = None
        self.interface = None
        self.ep_in = None
        self.ep_out = None
        self._claimed: list[int] = []
        self._open()

    def _find(self, info: UsbDeviceInfo):
        usb = self.usb
        kwargs = {
            "idVendor": info.vendor_id,
            "idProduct": info.product_id,
            "backend": self.backend,
        }
        try:
            dev = usb.core.find(bus=info.bus, address=info.address, **kwargs)
        except Exception:
            dev = None
        if dev is None:
            try:
                candidates = list(usb.core.find(find_all=True, **kwargs) or [])
            except Exception as exc:
                raise TransportError(f"USB find failed: {exc}") from exc
            for candidate in candidates:
                if int(getattr(candidate, "bus", 0) or 0) == info.bus and int(
                    getattr(candidate, "address", 0) or 0
                ) == info.address:
                    dev = candidate
                    break
            if dev is None and len(candidates) == 1:
                dev = candidates[0]
        if dev is None:
            raise TransportError(
                f"USB device {info.label} is no longer present or libusb cannot open it."
            )
        return dev

    def _open(self) -> None:
        try:
            self.dev.set_configuration()
        except Exception:
            # Some Android kernels reject re-setting an already active config.
            pass
        try:
            self.configuration = self.dev.get_active_configuration()
        except Exception as exc:
            raise TransportError(f"Could not read active USB configuration: {exc}") from exc

        chosen = None
        for interface in self.configuration:
            eps = list(interface)
            in_eps = [
                ep
                for ep in eps
                if self.usb.util.endpoint_direction(ep.bEndpointAddress)
                == self.usb.util.ENDPOINT_IN
                and (ep.bmAttributes & 0x3) in (_BULK, _INTERRUPT)
            ]
            out_eps = [
                ep
                for ep in eps
                if self.usb.util.endpoint_direction(ep.bEndpointAddress)
                == self.usb.util.ENDPOINT_OUT
                and (ep.bmAttributes & 0x3) in (_BULK, _INTERRUPT)
            ]
            if in_eps and out_eps:
                chosen = (interface, in_eps, out_eps)
                break
        if chosen is None:
            raise TransportError(
                f"No usable bulk/interrupt IN+OUT pair found on {self.info.label}"
            )

        interface, in_eps, out_eps = chosen
        self._claim(interface)
        self.interface = interface
        self.ep_in = in_eps[0]
        self.ep_out = out_eps[0]

        # The BROM usually exposes a single interface.  Prefer the first
        # endpoint pair but expose the descriptor sizes for chunking.
        self.max_read = int(getattr(self.ep_in, "wMaxPacketSize", 512) or 512)
        self.max_write = int(getattr(self.ep_out, "wMaxPacketSize", 512) or 512)

    def _claim(self, interface) -> None:
        number = int(interface.bInterfaceNumber)
        if number in self._claimed:
            return
        try:
            if self.dev.is_kernel_driver_active(number):
                try:
                    self.dev.detach_kernel_driver(number)
                except Exception:
                    pass
        except (NotImplementedError, AttributeError):
            pass
        try:
            self.usb.util.claim_interface(self.dev, number)
        except Exception as exc:
            raise PermissionDenied(
                f"Could not claim USB interface {number}: {exc}. "
                "Close other flashers (mtkclient, SP Flash Tool) and retry."
            ) from exc
        self._claimed.append(number)

    # ---- transport API -------------------------------------------------
    def write(self, data: bytes, timeout_ms: int | None = None) -> int:
        timeout = max(1, int(timeout_ms or self.timeout_ms))
        payload = bytes(data)
        try:
            if not payload:
                # A zero-length packet is meaningful for BROM data uploads:
                # it flushes the target's internal buffer at 8 KiB boundaries.
                self.ep_out.write(b"", timeout=timeout)
                return 0
            written = self.ep_out.write(payload, timeout=timeout)
        except Exception as exc:
            raise TransportError(f"USB bulk write failed: {exc}") from exc
        return int(written)

    def read(self, size: int, timeout_ms: int | None = None) -> bytes:
        if size <= 0:
            return b""
        timeout = max(1, int(timeout_ms or self.timeout_ms))
        try:
            data = self.ep_in.read(size, timeout=timeout)
        except Exception as exc:
            raise TransportError(f"USB bulk read failed: {exc}") from exc
        return bytes(data)

    def read_exact(self, size: int, timeout_ms: int | None = None) -> bytes:
        deadline = time.monotonic() + max(0.001, (timeout_ms or self.timeout_ms) / 1000)
        out = bytearray()
        while len(out) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TransportError(f"USB read timed out after {len(out)}/{size} bytes")
            chunk = self.read(size - len(out), max(1, int(remaining * 1000)))
            if not chunk:
                raise TransportError("USB read returned no data")
            out.extend(chunk)
        return bytes(out)

    def flush(self, timeout_ms: int = 50) -> None:
        while True:
            try:
                data = self.read(512, timeout_ms=timeout_ms)
                if not data:
                    return
            except TransportError:
                return

    def ctrl_transfer(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data_or_wLength: int | bytes | bytearray = 0,
        timeout_ms: int | None = None,
    ) -> bytes:
        timeout = max(1, int(timeout_ms or self.timeout_ms))
        try:
            result = self.dev.ctrl_transfer(
                bmRequestType,
                bRequest,
                wValue,
                wIndex,
                data_or_wLength,
                timeout=timeout,
            )
        except Exception as exc:
            raise TransportError(f"USB control transfer failed: {exc}") from exc
        return bytes(result) if result is not None else b""

    def close(self) -> None:
        for number in self._claimed:
            try:
                self.usb.util.release_interface(self.dev, number)
            except Exception:
                pass
        self._claimed.clear()
        try:
            self.usb.util.dispose_resources(self.dev)
        except Exception:
            pass

    def __enter__(self) -> "ClaimedUsbDevice":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


class UsbHost:
    """Enumeration, hotplug polling and opening of MediaTek USB devices."""

    def __init__(self, sysfs_root: Path = SYSFS_USB_ROOT) -> None:
        self.sysfs_root = Path(sysfs_root)

    def enumerate(self, include_other: bool = False) -> list[UsbDeviceInfo]:
        devices = enumerate_sysfs(self.sysfs_root)
        if not devices:
            try:
                devices = enumerate_pyusb()
            except TransportError:
                devices = []
        if include_other:
            return devices
        return [d for d in devices if d.mode is not DeviceMode.OTHER]

    def scan(self) -> list[UsbDeviceInfo]:
        return self.enumerate(include_other=True)

    def find(self, mode: DeviceMode | None = None) -> UsbDeviceInfo | None:
        for device in self.enumerate():
            if mode is None or device.mode is mode:
                return device
        return None

    def wait_for_device(
        self,
        mode: DeviceMode | None = None,
        timeout: float = 0.0,
        interval: float = 0.15,
        stop_event=None,
    ) -> UsbDeviceInfo | None:
        deadline = None if timeout <= 0 else time.monotonic() + timeout
        while True:
            device = self.find(mode=mode)
            if device is not None:
                return device
            if deadline is not None and time.monotonic() >= deadline:
                return None
            if stop_event is not None and stop_event.is_set():
                return None
            time.sleep(max(0.02, interval))

    def open(self, device: UsbDeviceInfo, timeout_ms: int = 1000) -> ClaimedUsbDevice:
        # Do not require uid 0 here: desktop udev rules can grant access to a
        # specific usbfs node.  The actual O_RDWR probe below is authoritative,
        # and --no-root-check relies on that.
        if not device.dev_path.exists():
            # Sysfs and usbfs are normally mounted together; a missing path is
            # a useful diagnostic rather than a mysterious libusb error.
            raise TransportError(
                f"Device node {device.dev_path} does not exist. "
                "Check that /dev/bus/usb is mounted and the cable is OTG-capable."
            )
        try:
            probe = os.open(device.dev_path, os.O_RDWR)
            os.close(probe)
        except PermissionError as exc:
            diag = root_diagnostics()
            raise PermissionDenied(
                f"Cannot open {device.dev_path}. Run as root (su -c), configure "
                "a udev rule for this device, or ensure SELinux permits the "
                f"termux domain to access usbfs. Diagnostics: {diag}"
            ) from exc
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ENODEV):
                raise TransportError(f"Device disappeared: {device.dev_path}") from exc
            raise TransportError(f"open({device.dev_path}) failed: {exc}") from exc
        return ClaimedUsbDevice(device, timeout_ms=timeout_ms)


class HotplugPoller:
    """Yield newly inserted devices, and remove events when they disappear."""

    def __init__(
        self,
        host: UsbHost | None = None,
        mode: DeviceMode | None = None,
        interval: float = 0.15,
    ) -> None:
        self.host = host or UsbHost()
        self.mode = mode
        self.interval = interval
        self._last: dict[tuple[int, int, int, int], UsbDeviceInfo] = {}

    def poll(self, stop_event=None) -> Iterator[tuple[str, UsbDeviceInfo]]:
        while True:
            if stop_event is not None and stop_event.is_set():
                return
            current = {
                d.key: d
                for d in self.host.enumerate(include_other=True)
                if self.mode is None or d.mode is self.mode
            }
            for key in list(self._last):
                if key not in current:
                    device = self._last.pop(key)
                    yield ("remove", device)
            for key, device in current.items():
                if key not in self._last:
                    self._last[key] = device
                    yield ("add", device)
            time.sleep(max(0.02, self.interval))


__all__ = [
    "BROM_PID",
    "MTK_VID",
    "PRELOADER_PID",
    "ClaimedUsbDevice",
    "DeviceMode",
    "HotplugPoller",
    "UsbDeviceInfo",
    "UsbHost",
    "check_root",
    "elevate",
    "enumerate_pyusb",
    "enumerate_sysfs",
    "is_root",
    "require_root",
    "root_diagnostics",
]
