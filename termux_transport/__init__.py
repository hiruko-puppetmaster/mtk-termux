"""USB transport for rooted Termux and Linux."""

from .usb_host import (  # noqa: F401
    BROM_PID,
    MTK_VID,
    PRELOADER_PID,
    ClaimedUsbDevice,
    DeviceMode,
    HotplugPoller,
    UsbDeviceInfo,
    UsbHost,
    check_root,
    elevate,
    enumerate_sysfs,
    require_root,
    root_diagnostics,
)

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
    "enumerate_sysfs",
    "require_root",
    "root_diagnostics",
]
