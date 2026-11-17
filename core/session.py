"""End-to-end BROM -> DA1 -> DA2 session orchestration."""

from __future__ import annotations

import logging
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path

from core.da_loader import DaEntry, DaLoader, PreloaderImage, load_preloader
from core.errors import (
    AuthError,
    DaError,
    ExploitNotSupported,
    MtkError,
    ProtocolError,
    TransportError,
)
from core.exploits import (
    ExploitResult,
    KamakiriExploit,
    load_payload,
    select_exploit,
)
from core.options import AppOptions, ProgressCallback, null_progress
from core.profiles import (
    AssetBundle,
    AssetDiscovery,
    Profile,
    ProfileStore,
    merge_selector,
)
from core.protocols import (
    BromAuthResult,
    BromProtocol,
    DAXMLProtocol,
    HwCode,
    TargetConfig,
    XFlashCmd,
    XFlashV5,
)
from termux_transport.usb_host import ClaimedUsbDevice, UsbDeviceInfo, UsbHost

LOG = logging.getLogger("mtk.session")


@dataclass
class SessionResult:
    device: UsbDeviceInfo
    hw_code: HwCode
    target_config: TargetConfig
    profile: Profile | None = None
    da_path: Path | None = None
    preloader_path: Path | None = None
    auth_path: Path | None = None
    exploit: ExploitResult | None = None
    da1_uploaded: bool = False
    da2_booted: bool = False
    protocol: str | None = None
    auth: BromAuthResult | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class ProbeResult:
    device: UsbDeviceInfo
    hw_code: HwCode
    target_config: TargetConfig
    brom_version: int | None = None


class DeviceSession:
    """Drive one target from BROM synchronization through DA2 startup."""

    def __init__(
        self,
        options: AppOptions,
        *,
        host: UsbHost | None = None,
        store: ProfileStore | None = None,
        discovery: AssetDiscovery | None = None,
        progress: ProgressCallback = null_progress,
        logger: logging.Logger | None = None,
    ) -> None:
        self.options = options
        self.host = host or UsbHost()
        self.store = store or ProfileStore(
            [options.profiles_dir] if options.profiles_dir else None
        )
        self.discovery = discovery or AssetDiscovery(options.extra_asset_dirs)
        self.progress = progress
        self.log = logger or LOG
        self.claimed: ClaimedUsbDevice | None = None
        self.brom: BromProtocol | None = None

    def _report(self, stage: str, message: str, fraction: float | None = None) -> None:
        self.log.info("[%s] %s", stage, message)
        try:
            self.progress(stage, message, fraction)
        except Exception:
            pass

    def open(self, device: UsbDeviceInfo) -> ClaimedUsbDevice:
        self._report("usb", f"opening {device.label}", 0.02)
        self.claimed = self.host.open(device, timeout_ms=1500)
        self.brom = BromProtocol(self.claimed, timeout_ms=1500, logger=self.log)
        return self.claimed

    def close(self) -> None:
        if self.claimed is not None:
            self.claimed.close()
            self.claimed = None

    def __enter__(self) -> "DeviceSession":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def probe(self, device: UsbDeviceInfo) -> ProbeResult:
        self.open(device)
        assert self.brom is not None
        self._report("brom", "synchronizing with Boot ROM", 0.15)
        self.brom.sync()
        self._report("brom", "reading HW_CODE", 0.3)
        hw = self.brom.get_hw_code()
        self._report("brom", f"HW_CODE {hw}", 0.45)
        try:
            target = self.brom.get_target_config()
        except ProtocolError:
            target = TargetConfig(raw=0)
        try:
            brom_version = self.brom.get_brom_version()
        except Exception:
            brom_version = None
        result = ProbeResult(device, hw, target, brom_version)
        self._report(
            "brom",
            f"probe complete: {hw}; target=0x{target.raw:08X}",
            0.5,
        )
        return result

    def run(self, device: UsbDeviceInfo) -> SessionResult:
        self.open(device)
        assert self.brom is not None
        self._report("brom", "synchronizing with Boot ROM", 0.05)
        self.brom.sync()
        hw = self.brom.get_hw_code()
        self._report("brom", f"HW_CODE {hw}", 0.12)
        try:
            target = self.brom.get_target_config()
        except ProtocolError:
            # Very old BROMs do not implement GET_TARGET_CONFIG.
            target = TargetConfig(raw=0)
            self.log.warning("BROM did not return a target config; assuming unprotected")
        self._report(
            "brom",
            f"target config 0x{target.raw:08X} "
            f"(SBC={target.sbc} SLA={target.sla} DAA={target.daa})",
            0.18,
        )

        bundle = self._resolve_bundle(hw, target)
        assert bundle.da_loader is not None and bundle.da_entry is not None
        entry = bundle.da_entry
        loader = bundle.da_loader
        self._report(
            "assets",
            f"DA {bundle.da} -> {entry.description}",
            0.25,
        )

        auth_result = None
        auth_bytes = None
        if bundle.auth:
            try:
                auth_bytes = bundle.auth.read_bytes()
            except OSError as exc:
                raise AuthError(f"cannot read auth bundle {bundle.auth}: {exc}") from exc
            if not auth_bytes:
                raise AuthError(f"auth bundle {bundle.auth} is empty")
        if auth_bytes:
            self._report("auth", f"sending auth bundle {bundle.auth.name}", 0.3)
            try:
                auth_result = self.brom.authenticate(auth=auth_bytes, target=target)
            except AuthError:
                if not self.options.allow_unsigned_da:
                    raise
                self.log.warning("Auth failed but allow_unsigned_da is set")
        elif target.sbc:
            self.log.warning(
                "Target reports SBC/secure boot, but no .auth bundle was provided. "
                "A stock signed DA may still work; if SEND_DA returns 0x1D0D you "
                "need a valid auth bundle/SLA signer."
            )

        exploit_result = None
        exploit_name = select_exploit(bundle.profile, self.options.exploit)
        if exploit_name == "kamakiri":
            payload = load_payload(self.options.payload or (bundle.profile.payload if bundle.profile else None))
            if payload is None:
                raise ExploitNotSupported("Kamakiri selected but no payload was supplied")
            assert bundle.profile is not None
            exploit = KamakiriExploit.from_profile(self.brom, bundle.profile, payload, self.log)
            self._report("exploit", "running Kamakiri", 0.35)
            exploit_result = exploit.run()
        elif exploit_name == "heapb8":
            raise ExploitNotSupported(
                "HeapB8 needs a DA2 memory backend and a firmware-matched payload. "
                "Use the library API after DA2 has started, or provide a DA2 backend."
            )
        else:
            self._report("exploit", "no exploit selected; using auth/stock DA path", 0.35)

        if entry.da1 is None:
            raise DaError("selected DA entry has no DA1 region")
        if entry.da2 is None:
            raise DaError("selected DA entry has no DA2 region")
        da1 = loader.da1_bytes(entry)
        da2 = loader.da2_bytes(entry)
        self._report(
            "da",
            f"DA1 {len(da1)} bytes @0x{entry.da1.address:08X}; "
            f"DA2 {len(da2)} bytes @0x{entry.da2.address:08X}",
            0.42,
        )
        self._report("da", "uploading DA1", 0.48)
        self.brom.send_da(
            entry.da1.address,
            da1,
            signature_length=entry.da1.signature_length,
        )
        self._report("da", "jumping to DA1", 0.58)
        self.brom.jump_da(entry.da1.address)
        da1_uploaded = True

        da2_body = da2[: max(0, len(da2) - entry.da2.signature_length)]
        if loader.v6 or entry.v6:
            protocol = "xml"
            self._report("da", "starting DA v6 XML protocol", 0.66)
            xml = DAXMLProtocol(self.claimed, timeout_ms=3000, logger=self.log)
            xml.get_command_result()  # initial CMD:START
            xml.setup()
            self._report("da", "booting DA2 over XML", 0.74)
            xml.boot_to(entry.da2.address, da2_body, timeout_s=0.5)
            xml.setup_hw_init()
            da2_booted = True
        else:
            protocol = "xflash"
            self._report("da", "starting XFlash V5 protocol", 0.66)
            xflash = XFlashV5(self.claimed, timeout_ms=3000, logger=self.log)
            sync = self.claimed.read_exact(1, timeout_ms=3000)
            if sync != b"\xC0":
                raise DaError(f"unexpected XFlash sync byte {sync.hex()}")
            xflash.sync()
            xflash.setup_env()
            xflash.setup_hw_init()
            packet = xflash.read_protocol()
            if len(packet) >= 4 and struct.unpack("<I", packet[:4])[0] == 0x434E5953:
                self.log.debug("XFlash DA1 sync confirmed")
            if bundle.preloader:
                try:
                    pre = load_preloader(bundle.preloader)
                    if pre.emi:
                        self._report("da", "sending preloader EMI/DRAM config", 0.7)
                        xflash.send_emi(pre.emi)
                except MtkError as exc:
                    self.log.warning("could not send preloader EMI: %s", exc)
            self._report("da", "booting DA2 over XFlash", 0.76)
            xflash.boot_to(entry.da2.address, da2_body, timeout_s=0.5)
            # boot_to validates the stage-2 status.  A best-effort info request
            # confirms that DA2 answers the normal XFlash command path.
            try:
                xflash.get_info(XFlashCmd.GET_DA_VERSION)
            except MtkError as exc:
                self.log.debug("DA2 info request failed: %s", exc)
            da2_booted = True

        self._report("done", "DA2 started successfully", 0.95)
        return SessionResult(
            device=device,
            hw_code=hw,
            target_config=target,
            profile=bundle.profile,
            da_path=bundle.da,
            preloader_path=bundle.preloader,
            auth_path=bundle.auth,
            exploit=exploit_result,
            da1_uploaded=da1_uploaded,
            da2_booted=da2_booted,
            protocol=protocol,
            auth=auth_result,
        )

    def _resolve_bundle(self, hw: HwCode, target: TargetConfig) -> AssetBundle:
        explicit = AssetBundle(
            da=self.options.da,
            preloader=self.options.preloader,
            auth=self.options.auth,
            payload=self.options.payload,
        )
        if explicit.da is None and explicit.preloader is None and not self.store.profiles:
            # Still allow a fully explicit manual invocation, but produce a
            # useful message if no assets are discoverable.
            self.log.debug("no profiles loaded; using explicit paths and discovery")
        bundle = merge_selector(
            hw.code,
            hw.version,
            explicit,
            self.store,
            self.discovery,
            hw_sub_code=None,
        )
        if bundle.missing():
            raise DaError(
                "Could not resolve a DA for HW_CODE "
                f"0x{hw.code:04X}. Place MTK_AllInOne_DA*.bin in a scanned "
                "directory, pass --da, or add a profile JSON. Missing: "
                + ", ".join(bundle.missing())
            )
        return bundle

    @staticmethod
    def validate_only(options: AppOptions) -> list[str]:
        """Validate explicit files without touching USB.  Returns messages."""

        messages: list[str] = []
        if options.da:
            loader = DaLoader.from_file(options.da)
            messages.append(f"DA: {len(loader.entries)} entries, v6={loader.v6}")
        if options.preloader:
            pre = load_preloader(options.preloader)
            messages.append(
                f"preloader: {len(pre.data)} bytes, EMI={'yes' if pre.emi else 'no'}, "
                f"version={pre.version}"
            )
        if options.auth:
            messages.append(f"auth: {options.auth} ({options.auth.stat().st_size} bytes)")
        if options.payload:
            payload = load_payload(options.payload)
            messages.append(f"payload: {len(payload or b'')} bytes")
        for error in ProfileStore(
            [options.profiles_dir] if options.profiles_dir else None
        ).errors:
            messages.append(f"profile error: {error}")
        return messages


__all__ = ["DeviceSession", "ProbeResult", "SessionResult"]
