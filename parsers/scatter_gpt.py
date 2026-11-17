"""MediaTek scatter-file and EFI GPT partition parsers.

Both parsers return plain dataclasses and never mutate the source file.  A
scatter file is a YAML-like text document with ``- partition_index:`` blocks;
the XML variant uses ``<partition>`` elements.  GPT parsing validates the
header and entry-array CRCs by default and supports 512-byte and 4K sectors.
"""

from __future__ import annotations

import io
import struct
import uuid
import zlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterable, Iterator, Mapping

from core.errors import ParserError

GPT_SIGNATURE = b"EFI PART"
GPT_HEADER_SIZE = 92


def parse_int(value: str | int | None, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    text = str(value).strip().strip("\"'")
    if not text or text in ("-", "NONE", "None", "none"):
        return default
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 10)
        except ValueError:
            return default


def _sector_size(value: int | None) -> int:
    size = int(value or 512)
    if size not in (512, 1024, 2048, 4096):
        raise ParserError(f"unsupported sector size {size}")
    return size


@dataclass(frozen=True)
class Partition:
    name: str
    start: int
    size: int
    index: int | None = None
    region: str | None = None
    storage: str | None = None
    file_name: str | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)

    @property
    def end(self) -> int:
        return self.start + self.size

    @property
    def sectors(self) -> int:
        return self.size // 512

    def __post_init__(self) -> None:
        if not self.name:
            raise ParserError("partition name is empty")
        if self.start < 0 or self.size < 0:
            raise ParserError(f"partition {self.name!r} has a negative extent")
        if self.start + self.size > 1 << 63:
            raise ParserError(f"partition {self.name!r} extent overflows 64-bit offsets")


@dataclass
class ScatterFile:
    partitions: list[Partition]
    platform: str | None = None
    project: str | None = None
    config_version: str | None = None
    path: str | None = None
    raw: Mapping[str, str] = field(default_factory=dict)

    def by_name(self) -> dict[str, Partition]:
        return {p.name: p for p in self.partitions}

    def get(self, name: str) -> Partition | None:
        return self.by_name().get(name)

    def validate(self) -> None:
        names = set()
        for part in self.partitions:
            if part.name in names:
                raise ParserError(f"duplicate partition name {part.name!r}")
            names.add(part.name)

        def check(parts: list[Partition]) -> None:
            ordered = sorted(parts, key=lambda p: (p.start, p.size))
            for left, right in zip(ordered, ordered[1:]):
                if left.size and right.start < left.end:
                    raise ParserError(
                        f"partitions {left.name!r} and {right.name!r} overlap "
                        f"(0x{left.start:X}-0x{left.end:X}, 0x{right.start:X})"
                    )

        # ``EMMC_BOOT_1`` and ``EMMC_USER`` are independent address spaces
        # and both commonly start at offset zero.  Compare only partitions in
        # the same explicit region; a partition without a region is checked
        # against every region (conservative).
        regions = {p.region for p in self.partitions if p.region}
        if not regions:
            check(self.partitions)
            return
        for region in regions:
            check(
                [
                    p
                    for p in self.partitions
                    if not p.region or p.region == region
                ]
            )

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "project": self.project,
            "config_version": self.config_version,
            "path": self.path,
            "partitions": [
                {
                    "name": p.name,
                    "start": p.start,
                    "size": p.size,
                    "index": p.index,
                    "region": p.region,
                    "storage": p.storage,
                    "file_name": p.file_name,
                    **({"attributes": dict(p.attributes)} if p.attributes else {}),
                }
                for p in self.partitions
            ],
        }


def _clean_scatter_value(value: str) -> str:
    value = value.strip()
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    return value


def parse_scatter(text: str, path: str | None = None) -> ScatterFile:
    """Parse a MediaTek scatter text or XML document."""

    if not text or not text.strip():
        raise ParserError("scatter file is empty")
    stripped = text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("<"):
        return _parse_scatter_xml(stripped, path)

    parts: list[Partition] = []
    current: dict[str, str] | None = None
    global_fields: dict[str, str] = {}

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        name = current.get("partition_name", "").strip()
        if not name:
            current = None
            return
        start_raw = current.get("physical_start_addr") or current.get("linear_start_addr")
        start = parse_int(start_raw)
        size = parse_int(current.get("partition_size"))
        index_raw = current.get("partition_index")
        index = parse_int(index_raw, -1)
        parts.append(
            Partition(
                name=name,
                start=start,
                size=size,
                index=index if index >= 0 else None,
                region=current.get("region") or None,
                storage=current.get("storage") or None,
                file_name=current.get("file_name") or None,
                attributes={k: v for k, v in current.items() if k not in _PARTITION_KEYS},
            )
        )
        current = None

    for line in text.splitlines():
        line = line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.lstrip().startswith("- partition_index:"):
            flush()
            current = {"partition_index": _clean_scatter_value(line.split(":", 1)[1])}
            continue
        if line.lstrip().startswith("- "):
            # A new non-partition block closes any partition block.
            flush()
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lstrip("-").strip()
        value = _clean_scatter_value(value)
        if current is not None:
            current[key] = value
        elif key in ("platform", "project", "config_version"):
            global_fields[key] = value

    flush()
    if not parts:
        raise ParserError("scatter file contains no partition blocks")
    result = ScatterFile(
        partitions=parts,
        platform=global_fields.get("platform"),
        project=global_fields.get("project"),
        config_version=global_fields.get("config_version"),
        path=path,
        raw=global_fields,
    )
    result.validate()
    return result


_PARTITION_KEYS = {
    "partition_index",
    "partition_name",
    "file_name",
    "is_download",
    "type",
    "linear_start_addr",
    "physical_start_addr",
    "partition_size",
    "region",
    "storage",
    "boundary_check",
    "is_reserved",
    "operation_type",
    "reserve",
}


def _parse_scatter_xml(text: str, path: str | None) -> ScatterFile:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ParserError(f"invalid scatter XML: {exc}") from exc
    parts: list[Partition] = []
    global_fields: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.split("}")[-1].lower()
        if tag not in ("partition", "partition_index", "part"):
            continue
        fields = {
            child.tag.split("}")[-1].lower(): (child.text or "").strip()
            for child in element
        }
        # Attributes are common in vendor XML variants.
        fields.update({k.lower(): str(v) for k, v in element.attrib.items()})
        name = fields.get("partition_name") or fields.get("name") or ""
        if not name:
            continue
        start = parse_int(
            fields.get("physical_start_addr") or fields.get("linear_start_addr")
        )
        size = parse_int(fields.get("partition_size") or fields.get("size"))
        index = parse_int(fields.get("partition_index"), -1)
        parts.append(
            Partition(
                name=name,
                start=start,
                size=size,
                index=index if index >= 0 else None,
                region=fields.get("region") or None,
                storage=fields.get("storage") or None,
                file_name=fields.get("file_name") or None,
                attributes={k: v for k, v in fields.items() if k not in _PARTITION_KEYS},
            )
        )
    for element in root.iter():
        tag = element.tag.split("}")[-1].lower()
        if tag in ("platform", "project", "config_version") and element.text:
            global_fields.setdefault(tag, element.text.strip())
    if not parts:
        raise ParserError("scatter XML contains no partition elements")
    result = ScatterFile(
        parts,
        platform=global_fields.get("platform"),
        project=global_fields.get("project"),
        config_version=global_fields.get("config_version"),
        path=path,
        raw=global_fields,
    )
    result.validate()
    return result


def parse_scatter_file(path: str | Path) -> ScatterFile:
    p = Path(path).expanduser()
    try:
        text = p.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise ParserError(f"cannot read scatter file {p}: {exc}") from exc
    return parse_scatter(text, path=str(p))


@dataclass(frozen=True)
class GptPartition:
    index: int
    type_guid: uuid.UUID
    unique_guid: uuid.UUID
    first_lba: int
    last_lba: int
    attributes: int
    name: str
    sector_size: int = 512

    @property
    def start(self) -> int:
        return self.first_lba * self.sector_size

    @property
    def size(self) -> int:
        return max(0, self.last_lba - self.first_lba + 1) * self.sector_size

    @property
    def end(self) -> int:
        return self.start + self.size

    def as_partition(self) -> Partition:
        return Partition(
            name=self.name or f"gpt{self.index}",
            start=self.start,
            size=self.size,
            index=self.index,
            attributes={
                "type_guid": str(self.type_guid),
                "unique_guid": str(self.unique_guid),
                "first_lba": str(self.first_lba),
                "last_lba": str(self.last_lba),
                "gpt_attributes": f"0x{self.attributes:016X}",
            },
        )


@dataclass
class GptTable:
    sector_size: int
    revision: int
    header_size: int
    header_crc: int
    current_lba: int
    backup_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: uuid.UUID
    entries_lba: int
    entry_count: int
    entry_size: int
    entries_crc: int
    partitions: list[GptPartition] = field(default_factory=list)
    path: str | None = None

    def by_name(self) -> dict[str, GptPartition]:
        return {p.name: p for p in self.partitions}

    def get(self, name: str) -> GptPartition | None:
        return self.by_name().get(name)

    def to_scatter(self) -> ScatterFile:
        parts = [p.as_partition() for p in self.partitions]
        return ScatterFile(parts, platform="GPT", path=self.path)

    def to_dict(self) -> dict:
        return {
            "sector_size": self.sector_size,
            "revision": self.revision,
            "current_lba": self.current_lba,
            "backup_lba": self.backup_lba,
            "first_usable_lba": self.first_usable_lba,
            "last_usable_lba": self.last_usable_lba,
            "disk_guid": str(self.disk_guid),
            "entries_lba": self.entries_lba,
            "entry_count": self.entry_count,
            "entry_size": self.entry_size,
            "path": self.path,
            "partitions": [
                {
                    "index": p.index,
                    "name": p.name,
                    "type_guid": str(p.type_guid),
                    "unique_guid": str(p.unique_guid),
                    "first_lba": p.first_lba,
                    "last_lba": p.last_lba,
                    "start": p.start,
                    "size": p.size,
                    "attributes": f"0x{p.attributes:016X}",
                }
                for p in self.partitions
            ],
        }


def _guid(raw: bytes) -> uuid.UUID:
    if len(raw) != 16:
        raise ParserError("GUID field is not 16 bytes")
    # EFI GUIDs store the first three fields little-endian.
    return uuid.UUID(bytes_le=raw)


def _parse_gpt_header(
    sector: bytes, sector_size: int, *, validate_crc: bool = True
) -> tuple[int, int, int, int, int, int, uuid.UUID, int, int, int, int]:
    if len(sector) < GPT_HEADER_SIZE:
        raise ParserError("GPT header sector is truncated")
    if sector[:8] != GPT_SIGNATURE:
        raise ParserError("GPT signature 'EFI PART' not found")
    revision, header_size, header_crc, _reserved = struct.unpack_from("<IIII", sector, 8)
    if header_size < GPT_HEADER_SIZE or header_size > sector_size:
        raise ParserError(f"invalid GPT header size {header_size}")
    current_lba, backup_lba, first_usable, last_usable = struct.unpack_from(
        "<QQQQ", sector, 24
    )
    disk_guid = _guid(sector[56:72])
    entries_lba, entry_count, entry_size, entries_crc = struct.unpack_from(
        "<QIII", sector, 72
    )
    if entry_size < 128 or entry_size % 8:
        raise ParserError(f"invalid GPT entry size {entry_size}")
    if entry_size > 4096:
        # The UEFI spec allows 128 * 2^n; larger values are not seen in the
        # wild and would let a malformed header request a huge allocation.
        raise ParserError(f"implausible GPT entry size {entry_size}")
    if entry_count == 0 or entry_count > 4096:
        raise ParserError(f"invalid GPT entry count {entry_count}")
    # Validate header CRC with the CRC field zeroed.
    check = bytearray(sector[:header_size])
    struct.pack_into("<I", check, 16, 0)
    if validate_crc and zlib.crc32(check) & 0xFFFFFFFF != header_crc:
        raise ParserError("GPT header CRC mismatch")
    return (
        revision,
        header_size,
        header_crc,
        current_lba,
        backup_lba,
        first_usable,
        last_usable,
        disk_guid,
        entries_lba,
        entry_count,
        entry_size,
        entries_crc,
    )


def parse_gpt(
    data: bytes,
    sector_size: int = 512,
    *,
    validate_crc: bool = True,
    path: str | None = None,
) -> GptTable:
    """Parse a primary GPT from a byte buffer.

    ``data`` must start at LBA 0 (protective MBR + primary header).  A buffer
    that starts exactly at the GPT header is also accepted when its entry
    array follows the header contiguously.
    """

    sector_size = _sector_size(sector_size)
    if len(data) < sector_size * 2:
        raise ParserError("GPT buffer is too small")
    start = 0
    if data[510:512] == b"\x55\xAA":
        # Protective MBR: entry 0 must be type 0xEE.
        mbr_type = data[446 + 4]
        if mbr_type == 0xEE:
            start = sector_size
    if data[start : start + 8] != GPT_SIGNATURE:
        # Some callers hand us a raw header; try offset zero.
        start = 0
    header_sector = data[start : start + sector_size]
    (
        revision,
        header_size,
        header_crc,
        current_lba,
        backup_lba,
        first_usable,
        last_usable,
        disk_guid,
        entries_lba,
        entry_count,
        entry_size,
        entries_crc,
    ) = _parse_gpt_header(header_sector, sector_size, validate_crc=validate_crc)

    entries_offset = (entries_lba - (current_lba if start == 0 else 0)) * sector_size
    if entries_offset < 0:
        raise ParserError("GPT entry array precedes the provided buffer")
    entries_length = entry_count * entry_size
    if entries_offset + entries_length > len(data):
        raise ParserError("GPT entry array extends beyond provided data")
    entries = data[entries_offset : entries_offset + entries_length]
    if validate_crc and zlib.crc32(entries) & 0xFFFFFFFF != entries_crc:
        raise ParserError("GPT entry-array CRC mismatch")

    partitions: list[GptPartition] = []
    for index in range(entry_count):
        raw = entries[index * entry_size : (index + 1) * entry_size]
        if len(raw) < 128 or raw[:16] == b"\x00" * 16:
            continue
        type_guid = _guid(raw[:16])
        unique_guid = _guid(raw[16:32])
        first_lba, last_lba, attributes = struct.unpack_from("<QQQ", raw, 32)
        name_raw = raw[56:128]
        name = name_raw.decode("utf-16-le", "replace").split("\x00", 1)[0].strip()
        if last_lba < first_lba or last_lba >= (1 << 64):
            raise ParserError(f"GPT partition {index} has an invalid LBA range")
        partitions.append(
            GptPartition(
                index=index + 1,
                type_guid=type_guid,
                unique_guid=unique_guid,
                first_lba=first_lba,
                last_lba=last_lba,
                attributes=attributes,
                name=name,
                sector_size=sector_size,
            )
        )
    return GptTable(
        sector_size=sector_size,
        revision=revision,
        header_size=header_size,
        header_crc=header_crc,
        current_lba=current_lba,
        backup_lba=backup_lba,
        first_usable_lba=first_usable,
        last_usable_lba=last_usable,
        disk_guid=disk_guid,
        entries_lba=entries_lba,
        entry_count=entry_count,
        entry_size=entry_size,
        entries_crc=entries_crc,
        partitions=partitions,
        path=path,
    )


def parse_gpt_file(
    path: str | Path,
    sector_size: int = 512,
    *,
    max_bytes: int = 16 * 1024 * 1024,
    validate_crc: bool = True,
) -> GptTable:
    p = Path(path).expanduser()
    try:
        with p.open("rb") as fh:
            data = fh.read(max_bytes)
    except OSError as exc:
        raise ParserError(f"cannot read GPT image {p}: {exc}") from exc
    return parse_gpt(data, sector_size=sector_size, validate_crc=validate_crc, path=str(p))


def read_gpt(
    reader: BinaryIO,
    sector_size: int = 512,
    *,
    validate_crc: bool = True,
    path: str | None = None,
) -> GptTable:
    """Read a GPT from a seekable binary stream (file or block device)."""

    sector_size = _sector_size(sector_size)
    reader.seek(0)
    mbr = reader.read(sector_size)
    if len(mbr) < sector_size:
        raise ParserError("could not read MBR")
    reader.seek(sector_size)
    header = reader.read(sector_size)
    if len(header) < GPT_HEADER_SIZE:
        raise ParserError("could not read GPT header")
    if header[:8] != GPT_SIGNATURE:
        raise ParserError("GPT header signature not found at LBA 1")
    # Reuse parse_gpt with a synthetic buffer containing header and entries.
    (
        _revision,
        _header_size,
        _header_crc,
        _current,
        _backup,
        _first,
        _last,
        _disk,
        entries_lba,
        entry_count,
        entry_size,
        _entries_crc,
    ) = _parse_gpt_header(header, sector_size, validate_crc=validate_crc)
    entries_length = entry_count * entry_size
    entries_offset = entries_lba * sector_size
    reader.seek(entries_offset)
    entries = reader.read(entries_length)
    if len(entries) != entries_length:
        raise ParserError("could not read GPT entry array")
    # Build a synthetic buffer with a protective MBR and place the entry array
    # at its real LBA so parse_gpt's validation logic sees the original layout.
    synthetic = bytearray(max(sector_size * 2, entries_offset + entries_length))
    synthetic[510:512] = b"\x55\xAA"
    synthetic[446 + 4] = 0xEE
    synthetic[sector_size : sector_size + sector_size] = header
    synthetic[entries_offset : entries_offset + entries_length] = entries
    return parse_gpt(
        bytes(synthetic),
        sector_size=sector_size,
        validate_crc=validate_crc,
        path=path,
    )


__all__ = [
    "GPT_SIGNATURE",
    "GptPartition",
    "GptTable",
    "Partition",
    "ScatterFile",
    "parse_gpt",
    "parse_gpt_file",
    "parse_int",
    "parse_scatter",
    "parse_scatter_file",
    "read_gpt",
]
