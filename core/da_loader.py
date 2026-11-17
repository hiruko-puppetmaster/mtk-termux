"""MediaTek Download Agent container and preloader EMI parser.

A vendor ``MTK_AllInOne_DA.bin`` is a small indexed container.  The parser
reads the index and region descriptors without executing anything, then
selects the entry matching the target ``HW_CODE``.  It is intentionally
forgiving about trailing bytes and vendor-specific padding.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from core.errors import DaError, ParserError

DA_HEADER_OFFSET = 0x68
DA_ENTRY_OFFSET = 0x6C
DA_ENTRY_OLD_STRIDE = 0xD8
DA_ENTRY_NEW_STRIDE = 0xDC
DA_ENTRY_HEADER = 20
DA_REGION = 20


@dataclass(frozen=True)
class DaRegion:
    offset: int
    length: int
    address: int
    start_offset: int
    signature_length: int

    def __post_init__(self) -> None:
        if self.offset < 0 or self.length < 0:
            raise ParserError("negative DA region offset/length")
        if self.signature_length < 0 or self.signature_length > self.length:
            raise ParserError("invalid DA signature length")

    @property
    def end(self) -> int:
        return self.offset + self.length


@dataclass
class DaEntry:
    magic: int
    hw_code: int
    hw_sub_code: int
    hw_version: int
    sw_version: int
    pagesize: int
    entry_region_index: int
    entry_region_count: int
    regions: list[DaRegion] = field(default_factory=list)
    old_loader: bool = False
    v6: bool = False

    def region(self, one_based_index: int) -> DaRegion | None:
        index = one_based_index - 1
        if 0 <= index < len(self.regions):
            return self.regions[index]
        return None

    @property
    def da1(self) -> DaRegion | None:
        # Vendor DA containers store DA1 in list slot 1.  Slot 0 is an
        # unsigned/alternate copy on many loaders; mtkclient and the vendor
        # tools consistently use slot 1 for the signed image that is uploaded.
        if len(self.regions) > 1:
            return self.regions[1]
        return self.regions[0] if self.regions else None

    @property
    def da2(self) -> DaRegion | None:
        return self.regions[2] if len(self.regions) > 2 else None

    @property
    def description(self) -> str:
        return (
            f"HW=0x{self.hw_code:04X} sub=0x{self.hw_sub_code:04X} "
            f"ver=0x{self.hw_version:04X} sw=0x{self.sw_version:04X} "
            f"regions={len(self.regions)}"
        )


@dataclass
class DaLoader:
    path: Path
    data: bytes
    entries: list[DaEntry]
    v6: bool = False

    @classmethod
    def from_bytes(cls, data: bytes, path: str | Path = "<memory>") -> "DaLoader":
        if len(data) < DA_HEADER_OFFSET + 4:
            raise ParserError("DA container is too small")
        count = struct.unpack_from("<I", data, DA_HEADER_OFFSET)[0]
        if count == 0 or count > 512:
            raise ParserError(f"invalid DA entry count {count}")
        old = data[DA_ENTRY_OFFSET + DA_ENTRY_OLD_STRIDE : DA_ENTRY_OFFSET + DA_ENTRY_OLD_STRIDE + 2] == b"\xDA\xDA"
        stride = DA_ENTRY_OLD_STRIDE if old else DA_ENTRY_NEW_STRIDE
        v6 = b"MTK_DA_v6" in data[:0x400] or b"MTK_DA_V6" in data[:0x400]
        entries: list[DaEntry] = []
        for i in range(count):
            base = DA_ENTRY_OFFSET + i * stride
            if old:
                header_size = 16
                if base + header_size > len(data):
                    break
                (
                    magic,
                    hw_code,
                    hw_sub_code,
                    hw_version,
                    pagesize,
                    _reserved3,
                    entry_region_index,
                    entry_region_count,
                ) = struct.unpack_from("<HHHHHHHH", data, base)
                sw_version = 0
            else:
                header_size = DA_ENTRY_HEADER
                if base + header_size > len(data):
                    break
                (
                    magic,
                    hw_code,
                    hw_sub_code,
                    hw_version,
                    sw_version,
                    _reserved1,
                    pagesize,
                    _reserved3,
                    entry_region_index,
                    entry_region_count,
                ) = struct.unpack_from("<HHHHHHHHHH", data, base)
            if entry_region_count > 64:
                # Not a DA entry; vendor containers occasionally contain a
                # blank index slot.
                continue
            regions: list[DaRegion] = []
            pos = base + header_size
            for _ in range(entry_region_count):
                if pos + DA_REGION > len(data):
                    break
                offset, length, address, start_offset, sig_len = struct.unpack_from(
                    "<IIIII", data, pos
                )
                try:
                    regions.append(DaRegion(offset, length, address, start_offset, sig_len))
                except ParserError:
                    break
                pos += DA_REGION
            entries.append(
                DaEntry(
                    magic=magic,
                    hw_code=hw_code,
                    hw_sub_code=hw_sub_code,
                    hw_version=hw_version,
                    sw_version=sw_version,
                    pagesize=pagesize,
                    entry_region_index=entry_region_index,
                    entry_region_count=entry_region_count,
                    regions=regions,
                    old_loader=old,
                    v6=v6,
                )
            )
        if not entries:
            raise ParserError("DA container contains no parsable entries")
        return cls(Path(path), data, entries, v6=v6)

    @classmethod
    def from_file(cls, path: str | Path, max_bytes: int = 512 * 1024 * 1024) -> "DaLoader":
        p = Path(path).expanduser()
        try:
            data = p.read_bytes()
        except OSError as exc:
            raise DaError(f"cannot read DA container {p}: {exc}") from exc
        if len(data) > max_bytes:
            raise DaError(f"DA container {p} is larger than {max_bytes} bytes")
        return cls.from_bytes(data, path=p)

    def select(
        self,
        hw_code: int,
        hw_version: int | None = None,
        sw_version: int | None = None,
        hw_sub_code: int | None = None,
    ) -> DaEntry | None:
        candidates = [e for e in self.entries if e.hw_code == hw_code]
        if not candidates:
            # Vendor containers sometimes use 0 for wildcard entries.
            candidates = [e for e in self.entries if e.hw_code == 0]
        if not candidates:
            return None
        # A loader from a newer SoC revision must not be uploaded to an older
        # target.  A zero version is treated as a wildcard.
        if hw_version is not None and hw_version != 0:
            candidates = [
                e
                for e in candidates
                if e.hw_version == 0 or e.hw_version <= hw_version
            ]
        if sw_version is not None and sw_version != 0:
            candidates = [
                e
                for e in candidates
                if e.sw_version == 0 or e.sw_version <= sw_version
            ]
        if not candidates:
            return None

        def score(entry: DaEntry) -> tuple[int, int, int, int]:
            exact_ver = 1 if hw_version is not None and entry.hw_version == hw_version else 0
            compatible_ver = (
                1 if hw_version is None or entry.hw_version <= hw_version else 0
            )
            exact_sw = 1 if sw_version is not None and entry.sw_version == sw_version else 0
            compatible_sw = 1 if sw_version is None or entry.sw_version <= sw_version else 0
            sub = 1 if hw_sub_code is not None and entry.hw_sub_code == hw_sub_code else 0
            return (exact_ver, compatible_ver, exact_sw + compatible_sw, sub)

        return max(candidates, key=score)

    def region_bytes(self, entry: DaEntry, region: DaRegion | None) -> bytes:
        if region is None:
            raise DaError("DA entry has no requested region")
        if region.offset + region.length > len(self.data):
            raise DaError(
                f"DA region extends past end of file: "
                f"0x{region.offset:X}+0x{region.length:X} > 0x{len(self.data):X}"
            )
        return self.data[region.offset : region.offset + region.length]

    def da1_bytes(self, entry: DaEntry) -> bytes:
        return self.region_bytes(entry, entry.da1)

    def da2_bytes(self, entry: DaEntry) -> bytes:
        return self.region_bytes(entry, entry.da2)

    def by_hwcode(self) -> dict[int, list[DaEntry]]:
        out: dict[int, list[DaEntry]] = {}
        for entry in self.entries:
            out.setdefault(entry.hw_code, []).append(entry)
        return out


@dataclass
class PreloaderImage:
    path: Path | None
    data: bytes
    emi: bytes | None = None
    version: int | None = None
    bloader_version: str | None = None
    dramsize: int | None = None


def extract_emi(data: bytes) -> PreloaderImage:
    """Extract the EMI/DRAM blob from a preloader image.

    The preloader contains an ``MTK_BLOADER_INFO_v`` marker and often an
    ``MMM`` EMI header.  This is a best-effort parser: preloader variants from
    different vendors pad the blob differently, so the raw image is always
    retained even when the EMI region cannot be identified.
    """

    if not data:
        raise ParserError("preloader image is empty")
    version = None
    bloader_version = None
    marker = b"MTK_BLOADER_INFO_v"
    idx = data.find(marker)
    if idx >= 0:
        try:
            version = int(data[idx + len(marker) : idx + len(marker) + 2].rstrip(b"\x00"))
        except ValueError:
            version = None
        end = data.find(b"\x00", idx)
        if end > idx:
            bloader_version = data[idx:end].decode("ascii", "replace")
    emi = None
    dramsize = None
    emi_idx = data.find(b"MMM\x01\x38\x00\x00\x00")
    if idx == 0:
        # Small XFlash-era preloaders start with the loader-info header and
        # are passed to INIT_EXT_RAM as-is (matches the vendor tool flow).
        emi = data
    elif emi_idx >= 0:
        blob = data[emi_idx:]
        try:
            mlen = struct.unpack_from("<I", blob, 0x20)[0]
            siglen = struct.unpack_from("<I", blob, 0x2C)[0]
            if 0 < mlen <= len(blob) and siglen <= mlen:
                body = blob[: mlen - siglen]
                if len(body) >= 4:
                    dramsize = struct.unpack("<I", body[-4:])[0]
                    if dramsize == 0 and len(body) > 0x800:
                        body = body[:-0x800]
                        if len(body) >= 4:
                            dramsize = struct.unpack("<I", body[-4:])[0]
                    if 0 < dramsize <= len(body) - 4:
                        region = body[-dramsize - 4 : -4]
                        mtk_bin = region.find(b"MTK_BIN")
                        if mtk_bin >= 0:
                            emi = region[mtk_bin + 0xC :]
        except struct.error:
            emi = None
    return PreloaderImage(
        Path("<memory>"),
        data,
        emi=emi,
        version=version,
        bloader_version=bloader_version,
        dramsize=dramsize,
    )


def load_preloader(path: str | Path) -> PreloaderImage:
    p = Path(path).expanduser()
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ParserError(f"cannot read preloader {p}: {exc}") from exc
    result = extract_emi(data)
    result.path = p
    return result


__all__ = [
    "DaEntry",
    "DaLoader",
    "DaRegion",
    "PreloaderImage",
    "extract_emi",
    "load_preloader",
]
