"""SoC profiles and automatic DA/preloader/auth asset selection."""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from core.da_loader import DaLoader
from core.errors import DaError, ParserError

DEFAULT_ASSET_DIRS = [
    Path.cwd(),
    Path.home() / "mtk",
    Path.home() / "Downloads",
    Path.home() / "Download",
    Path.home() / "storage" / "downloads",
    Path("/sdcard/Download"),
    Path("/sdcard/mtk"),
]

DA_PATTERNS = (
    "MTK_AllInOne_DA*.bin",
    "MTK_DA*.bin",
    "DA_*.bin",
    "*_DA.bin",
    "da_*.bin",
)
PRELOADER_PATTERNS = ("preloader*.bin", "preloader*.img", "*preloader*.bin")
AUTH_PATTERNS = ("*.auth", "*auth*.bin", "*.cert")


def parse_int(value, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return default
    try:
        return int(text, 0)
    except ValueError:
        return default


@dataclass
class Profile:
    name: str
    hw_code: int
    hw_sub_code: int | None = None
    hw_version: int | None = None
    sw_version: int | None = None
    da: Path | None = None
    preloader: Path | None = None
    auth: Path | None = None
    payload: Path | None = None
    exploit: str = "auto"
    watchdog: int | None = None
    brom_payload_addr: int | None = None
    var1: int | None = None
    blacklist_addr: int | None = None
    heap_base: int | None = None
    heap_size: int | None = None
    dpc_addr: int | None = None
    payload_addr: int | None = None
    notes: str = ""
    enabled: bool = True
    source: Path | None = None
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict, source: Path | None = None) -> "Profile":
        if not isinstance(data, dict):
            raise ParserError("profile root must be a JSON object")
        name = str(data.get("name") or data.get("soc") or data.get("chip") or "").strip()
        hw = data.get("hw_code", data.get("hwcode", data.get("hw")))
        if hw is None:
            raise ParserError("profile is missing hw_code")
        hw_code = parse_int(hw)
        if hw_code <= 0:
            raise ParserError(f"invalid hw_code {hw!r}")
        base = source.parent if source else Path.cwd()

        def path_of(key: str) -> Path | None:
            value = data.get(key)
            if not value:
                return None
            p = Path(str(value)).expanduser()
            if not p.is_absolute():
                p = base / p
            return p

        exploit = str(data.get("exploit", "auto")).strip().lower()
        if exploit not in ("auto", "kamakiri", "heapb8", "none"):
            raise ParserError(f"unsupported exploit {exploit!r} in profile")
        return cls(
            name=name or f"0x{hw_code:04X}",
            hw_code=hw_code,
            hw_sub_code=_optional_int(data.get("hw_sub_code", data.get("sub_code"))),
            hw_version=_optional_int(data.get("hw_version")),
            sw_version=_optional_int(data.get("sw_version")),
            da=path_of("da"),
            preloader=path_of("preloader"),
            auth=path_of("auth"),
            payload=path_of("payload"),
            exploit=exploit,
            watchdog=_optional_int(data.get("watchdog")),
            brom_payload_addr=_optional_int(
                data.get("brom_payload_addr", data.get("payload_addr_brom"))
            ),
            var1=_optional_int(data.get("var1")),
            blacklist_addr=_optional_int(data.get("blacklist_addr", data.get("blacklist"))),
            heap_base=_optional_int(data.get("heap_base")),
            heap_size=_optional_int(data.get("heap_size")),
            dpc_addr=_optional_int(data.get("dpc_addr")),
            payload_addr=_optional_int(data.get("payload_addr")),
            notes=str(data.get("notes", "")),
            enabled=_as_bool(data.get("enabled", True)),
            source=source,
            extra={k: v for k, v in data.items() if k not in _KNOWN_KEYS},
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "hw_code": f"0x{self.hw_code:04X}",
            "hw_sub_code": _hex_or_none(self.hw_sub_code),
            "hw_version": _hex_or_none(self.hw_version),
            "sw_version": _hex_or_none(self.sw_version),
            "da": str(self.da) if self.da else None,
            "preloader": str(self.preloader) if self.preloader else None,
            "auth": str(self.auth) if self.auth else None,
            "payload": str(self.payload) if self.payload else None,
            "exploit": self.exploit,
            "watchdog": _hex_or_none(self.watchdog),
            "brom_payload_addr": _hex_or_none(self.brom_payload_addr),
            "var1": _hex_or_none(self.var1),
            "blacklist_addr": _hex_or_none(self.blacklist_addr),
            "heap_base": _hex_or_none(self.heap_base),
            "heap_size": _hex_or_none(self.heap_size),
            "dpc_addr": _hex_or_none(self.dpc_addr),
            "payload_addr": _hex_or_none(self.payload_addr),
            "notes": self.notes,
            "enabled": self.enabled,
            **({"extra": self.extra} if self.extra else {}),
        }

    @property
    def supports_kamakiri(self) -> bool:
        return (
            self.watchdog is not None
            and self.brom_payload_addr is not None
            and self.var1 is not None
            and self.payload is not None
        )

    @property
    def supports_heapb8(self) -> bool:
        return (
            self.heap_base is not None
            and self.heap_size is not None
            and self.dpc_addr is not None
            and self.payload_addr is not None
            and self.payload is not None
        )


_KNOWN_KEYS = {
    "name",
    "soc",
    "chip",
    "hw_code",
    "hwcode",
    "hw",
    "hw_sub_code",
    "sub_code",
    "hw_version",
    "sw_version",
    "da",
    "preloader",
    "auth",
    "payload",
    "exploit",
    "watchdog",
    "brom_payload_addr",
    "payload_addr_brom",
    "var1",
    "blacklist_addr",
    "blacklist",
    "heap_base",
    "heap_size",
    "dpc_addr",
    "payload_addr",
    "notes",
    "enabled",
}


def _optional_int(value) -> int | None:
    if value is None or value == "":
        return None
    return parse_int(value, -1) if parse_int(value, -1) >= 0 else None


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "off", "disabled")
    return bool(value)


def _hex_or_none(value: int | None) -> str | None:
    return f"0x{value:08X}" if value is not None else None


def default_profile_dirs() -> list[Path]:
    return [
        Path.cwd() / "profiles",
        Path(__file__).resolve().parent.parent / "profiles",
        Path.home() / ".config" / "mtk-termux" / "profiles",
    ]


class ProfileStore:
    def __init__(self, dirs: Sequence[Path] | None = None) -> None:
        selected = default_profile_dirs() if dirs is None else dirs
        self.dirs = [Path(d).expanduser() for d in selected]
        self.profiles: list[Profile] = []
        self.errors: list[str] = []
        self.reload()

    def reload(self) -> None:
        self.profiles = []
        self.errors = []
        seen: set[Path] = set()
        for directory in self.dirs:
            if not directory.exists() or not directory.is_dir():
                continue
            for path in sorted(directory.glob("*.json")):
                resolved = path.resolve()
                if resolved in seen:
                    continue
                seen.add(resolved)
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    profile = Profile.from_dict(data, source=path)
                    if not profile.enabled:
                        continue
                    self.profiles.append(profile)
                except (OSError, ValueError, ParserError) as exc:
                    self.errors.append(f"{path}: {exc}")

    def best(
        self,
        hw_code: int,
        hw_version: int | None = None,
        hw_sub_code: int | None = None,
    ) -> Profile | None:
        candidates = [p for p in self.profiles if p.hw_code == hw_code]
        if hw_version not in (None, 0):
            candidates = [
                p for p in candidates if p.hw_version is None or p.hw_version <= hw_version
            ]
        if not candidates:
            return None

        def score(p: Profile) -> tuple[int, int, int, int]:
            exact_sub = 1 if hw_sub_code is not None and p.hw_sub_code == hw_sub_code else 0
            exact_ver = 1 if hw_version is not None and p.hw_version == hw_version else 0
            compatible = 1 if p.hw_version is None or hw_version is None or p.hw_version <= hw_version else 0
            return (exact_sub, exact_ver, compatible, 1 if p.da else 0)

        return max(candidates, key=score)

    def add(self, profile: Profile) -> None:
        self.profiles.append(profile)


@dataclass
class AssetBundle:
    da: Path | None = None
    preloader: Path | None = None
    auth: Path | None = None
    payload: Path | None = None
    profile: Profile | None = None
    da_loader: DaLoader | None = None
    da_entry = None

    def missing(self) -> list[str]:
        missing = []
        if self.da is None:
            missing.append("DA")
        if self.da_loader is None:
            missing.append("DA matching HW_CODE")
        return missing


def _walk_files(directory: Path, max_depth: int) -> Iterable[Path]:
    """Yield regular files under ``directory`` without deep traversal.

    ``Path.rglob`` descends the whole tree before the depth filter is applied,
    which is expensive on a Termux home/download directory full of unrelated
    files.  This walker stops at ``max_depth`` and skips hidden directories.
    """

    if max_depth < 0:
        return
    stack: list[tuple[Path, int]] = [(directory, 0)]
    while stack:
        current, depth = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_file(follow_symlinks=False):
                    yield Path(entry.path)
                elif (
                    depth < max_depth
                    and entry.is_dir(follow_symlinks=False)
                    and not entry.name.startswith(".")
                ):
                    stack.append((Path(entry.path), depth + 1))
            except OSError:
                continue


class AssetDiscovery:
    """Find DA/preloader/auth files in common Termux download locations."""
    def __init__(self, extra_dirs: Iterable[Path] | None = None) -> None:
        self.dirs: list[Path] = []
        seen: set[Path] = set()
        for directory in [*DEFAULT_ASSET_DIRS, *(extra_dirs or [])]:
            p = Path(directory).expanduser()
            if p.exists() and p.is_dir() and p.resolve() not in seen:
                seen.add(p.resolve())
                self.dirs.append(p)

    def files(self, patterns: Sequence[str], max_depth: int = 3) -> list[Path]:
        found: list[Path] = []
        seen: set[Path] = set()
        for directory in self.dirs:
            for path in _walk_files(directory, max_depth):
                if not any(fnmatch.fnmatch(path.name, pattern) for pattern in patterns):
                    continue
                if path.resolve() not in seen:
                    seen.add(path.resolve())
                    found.append(path)
        return sorted(found, key=lambda p: (len(p.parts), str(p)))

    def da_candidates(self) -> list[Path]:
        return self.files(DA_PATTERNS)

    def preloader_candidates(self) -> list[Path]:
        return self.files(PRELOADER_PATTERNS)

    def auth_candidates(self) -> list[Path]:
        return self.files(AUTH_PATTERNS)

    def find_da_for_hw(self, hw_code: int, hw_version: int | None = None):
        matches = []
        for path in self.da_candidates():
            try:
                loader = DaLoader.from_file(path)
            except (DaError, ParserError, OSError):
                continue
            entry = loader.select(hw_code, hw_version)
            if entry is not None:
                matches.append((path, loader, entry))
        if not matches:
            return None
        return matches[0]

    def find_preloader(self, hw_code: int, profile: Profile | None = None) -> Path | None:
        if profile and profile.preloader and profile.preloader.exists():
            return profile.preloader
        candidates = self.preloader_candidates()
        token = f"{hw_code:04x}"
        preferred = [p for p in candidates if token in p.name.lower()]
        if preferred:
            return preferred[0]
        return candidates[0] if len(candidates) == 1 else None

    def find_auth(self, hw_code: int, profile: Profile | None = None) -> Path | None:
        if profile and profile.auth and profile.auth.exists():
            return profile.auth
        candidates = self.auth_candidates()
        token = f"{hw_code:04x}"
        preferred = [p for p in candidates if token in p.name.lower()]
        if preferred:
            return preferred[0]
        return candidates[0] if len(candidates) == 1 else None


def merge_selector(
    hw_code: int,
    hw_version: int | None,
    explicit: AssetBundle,
    store: ProfileStore,
    discovery: AssetDiscovery,
    hw_sub_code: int | None = None,
) -> AssetBundle:
    """Resolve explicit paths first, then profile, then directory scan."""

    profile = store.best(hw_code, hw_version=hw_version, hw_sub_code=hw_sub_code)
    bundle = explicit
    bundle.profile = profile
    if bundle.da is None and profile and profile.da and profile.da.is_file():
        bundle.da = profile.da
    if bundle.preloader is None:
        bundle.preloader = discovery.find_preloader(hw_code, profile)
    if bundle.auth is None:
        bundle.auth = discovery.find_auth(hw_code, profile)
    if (
        bundle.payload is None
        and profile
        and profile.payload
        and profile.payload.is_file()
    ):
        bundle.payload = profile.payload

    if bundle.da is not None:
        loader = DaLoader.from_file(bundle.da)
        bundle.da_loader = loader
        bundle.da_entry = loader.select(
            hw_code, hw_version=hw_version, hw_sub_code=hw_sub_code
        )
        if bundle.da_entry is None:
            raise DaError(
                f"DA {bundle.da} has no entry for HW_CODE 0x{hw_code:04X}"
            )
    else:
        found = discovery.find_da_for_hw(hw_code, hw_version)
        if found:
            bundle.da, bundle.da_loader, bundle.da_entry = found
    return bundle


__all__ = [
    "AssetBundle",
    "AssetDiscovery",
    "Profile",
    "ProfileStore",
    "default_profile_dirs",
    "merge_selector",
]
