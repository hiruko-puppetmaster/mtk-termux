"""MediaTek BROM, XFlash V5 and DA v6 XML protocol implementations.

Wire conventions used here are intentionally explicit:

* BROM commands are echoed byte-for-byte and multi-byte fields are big-endian.
* XFlash uses a little-endian ``0xFEEEEEEF`` 12-byte header with optional
  4-byte priority for ``DT_MESSAGE`` packets.
* DA v6 XML is carried inside XFlash protocol-flow packets and is
  NUL-terminated.  Host acknowledgements are ``OK`` / ``OK@0x...`` strings.

The classes do not depend on pyusb; they only need an object implementing the
small ``ByteTransport`` protocol below.  This makes the wire logic testable
without a phone attached.
"""

from __future__ import annotations

import logging
import struct
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Protocol, Sequence, runtime_checkable

from core.errors import (
    AuthError,
    DaError,
    HandshakeError,
    ProtocolError,
    TransportError,
)

BROM_SYNC = b"\xA0\x0A\x50\x05"
BROM_SYNC_RESPONSE = b"\x5F\xF5\xAF\xFA"
XFLASH_MAGIC = 0xFEEEEEEF
XFLASH_SYNC_SIGNAL = 0x434E5953
DT_PROTOCOL_FLOW = 1
DT_MESSAGE = 2


@runtime_checkable
class ByteTransport(Protocol):
    def write(self, data: bytes, timeout_ms: int | None = None) -> int: ...
    def read(self, size: int, timeout_ms: int | None = None) -> bytes: ...
    def read_exact(self, size: int, timeout_ms: int | None = None) -> bytes: ...
    def flush(self, timeout_ms: int = 50) -> None: ...
    def ctrl_transfer(
        self,
        bmRequestType: int,
        bRequest: int,
        wValue: int = 0,
        wIndex: int = 0,
        data_or_wLength: int | bytes | bytearray = 0,
        timeout_ms: int | None = None,
    ) -> bytes: ...


def _read_exact(transport: ByteTransport, size: int, timeout_ms: int) -> bytes:
    if hasattr(transport, "read_exact"):
        return bytes(transport.read_exact(size, timeout_ms=timeout_ms))
    deadline = time.monotonic() + max(0.001, timeout_ms / 1000)
    out = bytearray()
    while len(out) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransportError(f"read timed out after {len(out)}/{size} bytes")
        chunk = bytes(transport.read(size - len(out), timeout_ms=max(1, int(remaining * 1000))))
        if not chunk:
            raise TransportError("transport returned no data")
        out.extend(chunk)
    return bytes(out)


def _write_all(transport: ByteTransport, data: bytes, timeout_ms: int) -> None:
    view = memoryview(data)
    pos = 0
    while pos < len(view):
        written = int(transport.write(bytes(view[pos:]), timeout_ms=timeout_ms))
        if written <= 0:
            raise TransportError("transport wrote zero bytes")
        pos += written


def _flush(transport: ByteTransport) -> None:
    try:
        transport.flush()
    except Exception:
        pass


def _byteswap32(value: int) -> int:
    return int.from_bytes(value.to_bytes(4, "little"), "big")


class BromStatus(int):
    """Small helper for readable status formatting."""


@dataclass(frozen=True)
class HwCode:
    code: int
    version: int

    def __str__(self) -> str:
        return f"0x{self.code:04X}/0x{self.version:04X}"


@dataclass(frozen=True)
class TargetConfig:
    raw: int
    sbc: bool = False
    sla: bool = False
    daa: bool = False
    epp: bool = False
    cert: bool = False
    mem_read: bool = False
    mem_write: bool = False
    cmd_c8_blocked: bool = False

    @classmethod
    def from_raw(cls, raw: int) -> "TargetConfig":
        return cls(
            raw=raw,
            sbc=bool(raw & 0x1),
            sla=bool(raw & 0x2),
            daa=bool(raw & 0x4),
            epp=bool(raw & 0x8),
            cert=bool(raw & 0x10),
            mem_read=bool(raw & 0x20),
            mem_write=bool(raw & 0x40),
            cmd_c8_blocked=bool(raw & 0x80),
        )


@dataclass(frozen=True)
class BromAuthResult:
    cert_sent: bool = False
    auth_sent: bool = False
    sla_passed: bool = False
    status: int = 0


class BromProtocol:
    """BROM/Preloader command protocol."""

    SYNC = BROM_SYNC
    SYNC_RESPONSE = BROM_SYNC_RESPONSE

    CMD_READ16 = 0xD0
    CMD_READ32 = 0xD1
    CMD_WRITE16 = 0xD2
    CMD_WRITE32 = 0xD4
    CMD_JUMP_DA = 0xD5
    CMD_JUMP_DA64 = 0xDE
    CMD_SEND_DA = 0xD7
    CMD_GET_TARGET_CONFIG = 0xD8
    CMD_SEND_CERT = 0xE0
    CMD_SEND_AUTH = 0xE2
    CMD_SLA = 0xE3
    CMD_GET_HW_CODE = 0xFD
    CMD_GET_BL_VER = 0xFE
    CMD_GET_VERSION = 0xFF
    CMD_BROM_LOG = 0xDD
    CMD_BROM_LOG_NEW = 0xDF

    def __init__(
        self,
        transport: ByteTransport,
        timeout_ms: int = 1000,
        logger: logging.Logger | None = None,
        sla_signer=None,
    ) -> None:
        self.transport = transport
        self.timeout_ms = max(50, int(timeout_ms))
        self.log = logger or logging.getLogger("mtk.brom")
        self.sla_signer = sla_signer

    def sync(self, attempts: int = 8, per_byte_timeout_ms: int = 500) -> None:
        last = b""
        for attempt in range(max(1, attempts)):
            _flush(self.transport)
            matched = True
            for byte in self.SYNC:
                try:
                    _write_all(self.transport, bytes([byte]), per_byte_timeout_ms)
                    got = _read_exact(self.transport, 1, per_byte_timeout_ms)
                except TransportError:
                    matched = False
                    break
                last = got
                if got[0] != ((~byte) & 0xFF):
                    matched = False
                    break
            if matched:
                self.log.debug("BROM handshake complete")
                return
            time.sleep(0.05)
        raise HandshakeError(
            "BROM handshake failed. Power the phone off, hold the BROM key "
            "combination and reconnect the OTG cable. Last byte: "
            f"{last.hex() if last else 'none'}"
        )

    def echo(self, data: bytes) -> None:
        _write_all(self.transport, data, self.timeout_ms)
        got = _read_exact(self.transport, len(data), self.timeout_ms)
        if got != data:
            raise ProtocolError(
                f"echo mismatch: sent {data.hex()} received {got.hex()}"
            )

    def echo_u32(self, value: int, little_endian: bool = False) -> None:
        self.echo(struct.pack("<I" if little_endian else ">I", value & 0xFFFFFFFF))

    def read_u16(self, little_endian: bool = False) -> int:
        return struct.unpack("<H" if little_endian else ">H", _read_exact(self.transport, 2, self.timeout_ms))[0]

    def read_u32(self, little_endian: bool = False) -> int:
        return struct.unpack("<I" if little_endian else ">I", _read_exact(self.transport, 4, self.timeout_ms))[0]

    def get_hw_code(self) -> HwCode:
        self.echo(bytes([self.CMD_GET_HW_CODE]))
        raw = _read_exact(self.transport, 4, self.timeout_ms)
        code, version = struct.unpack(">HH", raw)
        return HwCode(code, version)

    def get_bl_version(self) -> int:
        # These commands return the value directly rather than echoing.
        _write_all(self.transport, bytes([self.CMD_GET_BL_VER]), self.timeout_ms)
        return _read_exact(self.transport, 1, self.timeout_ms)[0]

    def get_brom_version(self) -> int:
        _write_all(self.transport, bytes([self.CMD_GET_VERSION]), self.timeout_ms)
        return _read_exact(self.transport, 1, self.timeout_ms)[0]

    def get_target_config(self) -> TargetConfig:
        self.echo(bytes([self.CMD_GET_TARGET_CONFIG]))
        raw = _read_exact(self.transport, 6, self.timeout_ms)
        config, status = struct.unpack(">IH", raw)
        if status > 0xFF:
            raise ProtocolError(f"GET_TARGET_CONFIG status 0x{status:04X}")
        return TargetConfig.from_raw(config)

    def read32(self, address: int, count: int = 1) -> list[int]:
        if count < 1 or count > 0x4000:
            raise ValueError("count must be between 1 and 0x4000")
        self.echo(bytes([self.CMD_READ32]))
        self.echo_u32(address)
        self.echo_u32(count)
        status = self.read_u16()
        if status > 0xFF:
            raise ProtocolError(f"READ32 @0x{address:08X} status 0x{status:04X}")
        data = _read_exact(self.transport, 4 * count, self.timeout_ms)
        status2 = self.read_u16()
        if status2 > 0xFF:
            raise ProtocolError(f"READ32 completion status 0x{status2:04X}")
        return list(struct.unpack(f">{count}I", data))

    def write32(self, address: int, values: int | Sequence[int]) -> None:
        if isinstance(values, int):
            values = [values]
        values = list(values)
        if not values or len(values) > 0x4000:
            raise ValueError("values must contain 1..0x4000 words")
        self.echo(bytes([self.CMD_WRITE32]))
        self.echo_u32(address)
        self.echo_u32(len(values))
        status = self.read_u16()
        if status > 0xFF:
            raise ProtocolError(f"WRITE32 @0x{address:08X} status 0x{status:04X}")
        for value in values:
            self.echo_u32(value & 0xFFFFFFFF)
        status2 = self.read_u16()
        if status2 > 0xFF:
            raise ProtocolError(f"WRITE32 completion status 0x{status2:04X}")

    @staticmethod
    def prepare_data(data: bytes, signature: bytes = b"", max_size: int = 0) -> tuple[int, bytes]:
        body = data[:max_size] if max_size else data
        payload = body + signature
        if len(payload) % 2:
            payload += b"\x00"
        checksum = 0
        for pos in range(0, len(payload), 2):
            checksum ^= struct.unpack("<H", payload[pos : pos + 2])[0]
        return checksum, payload

    def _upload_data(self, data: bytes, expected_checksum: int, chunk_size: int = 0x400) -> None:
        pos = 0
        while pos < len(data):
            chunk = data[pos : pos + chunk_size]
            _write_all(self.transport, chunk, self.timeout_ms)
            pos += len(chunk)
            if pos % 0x2000 == 0:
                # BROM implementations flush their upload buffer at 8 KiB
                # boundaries; a zero-length packet requests that flush.
                try:
                    self.transport.write(b"", timeout_ms=self.timeout_ms)
                except Exception:
                    pass
        # A zero-length packet terminates the transfer on many BROM versions.
        try:
            self.transport.write(b"", timeout_ms=self.timeout_ms)
        except Exception:
            pass
        # The BROM verifies the loaded image before answering; reading the
        # trailer immediately produces timeouts on slower targets.
        time.sleep(0.12)
        trailer = _read_exact(self.transport, 4, self.timeout_ms)
        checksum, status = struct.unpack(">HH", trailer)
        if checksum not in (expected_checksum, 0):
            self.log.warning(
                "DA upload checksum 0x%04X does not match expected 0x%04X",
                checksum,
                expected_checksum,
            )
        if status > 0xFF:
            raise ProtocolError(f"DA upload failed with status 0x{status:04X}")

    def send_da(
        self,
        address: int,
        data: bytes,
        signature_length: int = 0,
        chunk_size: int = 0x400,
    ) -> None:
        if signature_length < 0 or signature_length > len(data):
            raise ValueError("invalid signature length")
        body = data[:-signature_length] if signature_length else data
        signature = data[-signature_length:] if signature_length else b""
        checksum, payload = self.prepare_data(body, signature)
        self.echo(bytes([self.CMD_SEND_DA]))
        self.echo_u32(address)
        self.echo_u32(len(payload))
        self.echo_u32(signature_length)
        status = self.read_u16()
        if status == 0x1D0D:
            if self.sla_signer is None:
                raise AuthError(
                    "The BROM requested SLA before accepting DA1, but no SLA "
                    "signer was supplied. Pass a signed auth bundle or an SLA key."
                )
            self.handle_sla(self.sla_signer)
            status = 0
        if status > 0xFF:
            raise ProtocolError(f"SEND_DA status 0x{status:04X}")
        self._upload_data(payload, checksum, chunk_size=chunk_size)

    def jump_da(self, address: int, timeout_s: float = 0.2) -> None:
        self.echo(bytes([self.CMD_JUMP_DA]))
        _write_all(self.transport, struct.pack(">I", address), self.timeout_ms)
        echoed = self.read_u32()
        if echoed != address:
            raise ProtocolError(
                f"JUMP_DA echoed 0x{echoed:08X}, expected 0x{address:08X}"
            )
        status = self.read_u16()
        if status > 0xFF:
            raise ProtocolError(f"JUMP_DA status 0x{status:04X}")
        time.sleep(max(0.0, timeout_s))

    def send_root_cert(self, cert: bytes) -> None:
        checksum, payload = self.prepare_data(b"", cert)
        self.echo(bytes([self.CMD_SEND_CERT]))
        self.echo_u32(len(payload))
        status = self.read_u16()
        if status > 0xFF:
            raise AuthError(f"SEND_CERT status 0x{status:04X}")
        self._upload_data(payload, checksum)

    def send_auth(self, auth: bytes) -> None:
        checksum, payload = self.prepare_data(auth, b"", len(auth))
        self.echo(bytes([self.CMD_SEND_AUTH]))
        _write_all(self.transport, struct.pack(">I", len(payload)), self.timeout_ms)
        expected = self.read_u32()
        if expected != len(payload):
            raise AuthError(
                f"SEND_AUTH length mismatch: host={len(payload)} target={expected}"
            )
        status = self.read_u16()
        if status == 0x1D0C:
            return
        if status > 0xFF:
            raise AuthError(f"SEND_AUTH status 0x{status:04X}")
        self._upload_data(payload, checksum)

    def handle_sla(self, signer) -> bool:
        """Sign the BROM challenge with a caller-supplied RSA signer.

        ``signer`` is a callable ``(challenge: bytes) -> bytes``.  BROM SLA
        private keys are not distributed with this tool.
        """

        self.echo(bytes([self.CMD_SLA]))
        status = self.read_u16()
        if status == 0x7017:
            return True
        if status > 0xFF:
            raise AuthError(f"SLA status 0x{status:04X}")
        challenge_length = self.read_u32()
        if challenge_length == 0 or challenge_length > 0x1000:
            raise AuthError(f"invalid SLA challenge length {challenge_length}")
        challenge = _read_exact(self.transport, challenge_length, self.timeout_ms)
        response = signer(challenge)
        if not response:
            raise AuthError("SLA signer returned an empty response")
        _write_all(self.transport, struct.pack("<I", len(response)), self.timeout_ms)
        target_length = self.read_u32()
        if target_length != len(response):
            raise AuthError(
                f"SLA response length mismatch: host={len(response)} target={target_length}"
            )
        status = self.read_u16()
        if status > 0xFF:
            raise AuthError(f"SLA challenge status 0x{status:04X}")
        _write_all(self.transport, response, self.timeout_ms)
        final = self.read_u32()
        if final >= 0xFF and final != 0x7017:
            raise AuthError(f"SLA authentication failed: 0x{final:08X}")
        return True

    def authenticate(
        self,
        auth: bytes | None = None,
        cert: bytes | None = None,
        signer=None,
        target: TargetConfig | None = None,
    ) -> BromAuthResult:
        """Send the root certificate and/or auth (DAA) bundle.

        The BROM issues the SLA challenge while processing ``SEND_DA`` (status
        ``0x1D0D``), so SLA is not started here unless the caller explicitly
        passes a ``signer`` for an already-pending challenge.  A signer passed
        here is remembered for the later ``SEND_DA`` exchange.
        """

        cert_sent = False
        auth_sent = False
        sla_passed = False
        if cert:
            self.send_root_cert(cert)
            cert_sent = True
        if auth:
            self.send_auth(auth)
            auth_sent = True
        if signer is not None:
            self.sla_signer = signer
        elif target is not None and target.sla:
            self.log.warning(
                "Target reports SLA. If SEND_DA returns 0x1D0D, an SLA signer "
                "must be configured; a valid signed DA may still load."
            )
        return BromAuthResult(cert_sent, auth_sent, sla_passed, 0)


# ---------------------------------------------------------------------------
# XFlash V5
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class XFlashPacket:
    datatype: int
    data: bytes
    priority: int | None = None


@dataclass(frozen=True)
class XFlashCmd:
    UNKNOWN = 0x010000
    DOWNLOAD = 0x010001
    UPLOAD = 0x010002
    FORMAT = 0x010003
    WRITE_DATA = 0x010004
    READ_DATA = 0x010005
    FORMAT_PARTITION = 0x010006
    SHUTDOWN = 0x010007
    BOOT_TO = 0x010008
    DEVICE_CTRL = 0x010009
    INIT_EXT_RAM = 0x01000A
    SWITCH_USB_SPEED = 0x01000B
    READ_OTP_ZONE = 0x01000C
    WRITE_OTP_ZONE = 0x01000D
    WRITE_EFUSE = 0x01000E
    READ_EFUSE = 0x01000F
    SETUP_ENVIRONMENT = 0x010100
    SETUP_HW_INIT_PARAMS = 0x010101
    SET_BMT_PERCENTAGE = 0x020001
    SET_BATTERY_OPT = 0x020002
    SET_CHECKSUM_LEVEL = 0x020003
    SET_RESET_KEY = 0x020004
    SET_HOST_INFO = 0x020005
    SET_META_BOOT_MODE = 0x020006
    SET_EMMC_HWRESET_PIN = 0x020007
    SET_GENERATE_GPX = 0x020008
    SET_REGISTER_VALUE = 0x020009
    SET_EXTERNAL_SIG = 0x02000A
    SET_REMOTE_SEC_POLICY = 0x02000B
    SET_ALL_IN_ONE_SIG = 0x02000C
    SET_RSC_INFO = 0x02000D
    GET_EMMC_INFO = 0x040001
    GET_NAND_INFO = 0x040002
    GET_NOR_INFO = 0x040003
    GET_UFS_INFO = 0x040004
    GET_DA_VERSION = 0x040005
    GET_EXPIRE_DATA = 0x040006
    GET_PACKET_LENGTH = 0x040007
    GET_RANDOM_ID = 0x040008
    GET_PARTITION_TBL_CATA = 0x040009
    GET_CONNECTION_AGENT = 0x04000A
    GET_USB_SPEED = 0x04000B
    GET_RAM_INFO = 0x04000C
    GET_CHIP_ID = 0x04000D
    GET_OTP_LOCK_STATUS = 0x04000E
    GET_BATTERY_VOLTAGE = 0x04000F
    GET_RPMB_STATUS = 0x040010
    GET_EXPIRE_DATE = 0x040011
    GET_DRAM_TYPE = 0x040012
    GET_DEV_FW_INFO = 0x040013
    GET_HRID = 0x040014
    GET_ERROR_DETAIL = 0x040015
    SLA_ENABLED_STATUS = 0x040016


class XFlashV5:
    """XFlash binary protocol (DA1/DA2 stage communication)."""

    def __init__(
        self,
        transport: ByteTransport,
        timeout_ms: int = 2000,
        logger: logging.Logger | None = None,
    ) -> None:
        self.transport = transport
        self.timeout_ms = max(50, int(timeout_ms))
        self.log = logger or logging.getLogger("mtk.xflash")

    def send(self, data: bytes | int, datatype: int = DT_PROTOCOL_FLOW) -> None:
        if isinstance(data, int):
            payload = struct.pack("<I", data & 0xFFFFFFFF)
        else:
            payload = bytes(data)
        header = struct.pack("<III", XFLASH_MAGIC, datatype, len(payload))
        _write_all(self.transport, header, self.timeout_ms)
        if payload:
            _write_all(self.transport, payload, self.timeout_ms)

    def send_u32(self, value: int) -> None:
        self.send(struct.pack("<I", value & 0xFFFFFFFF))

    def read_packet(self) -> XFlashPacket:
        header = _read_exact(self.transport, 12, self.timeout_ms)
        magic, datatype, length = struct.unpack("<III", header)
        if magic != XFLASH_MAGIC:
            raise ProtocolError(
                f"XFlash bad magic 0x{magic:08X}; expected 0x{XFLASH_MAGIC:08X}"
            )
        priority = None
        if datatype == DT_MESSAGE:
            if length < 4:
                raise ProtocolError("XFlash message packet is shorter than priority")
            priority = struct.unpack("<I", _read_exact(self.transport, 4, self.timeout_ms))[0]
            length -= 4
        if length > 0x1000000:
            raise ProtocolError(f"XFlash packet length {length:#x} is unreasonable")
        data = _read_exact(self.transport, length, self.timeout_ms) if length else b""
        if datatype == DT_MESSAGE:
            try:
                text = data.rstrip(b"\x00").decode("utf-8", "replace")
                self.log.debug("[DA] %s", text)
            except Exception:
                pass
        return XFlashPacket(datatype, data, priority)

    def read_protocol(self) -> bytes:
        for _ in range(100):
            packet = self.read_packet()
            if packet.datatype == DT_PROTOCOL_FLOW:
                return packet.data
        raise ProtocolError("too many DA message packets without protocol-flow data")

    def status(self) -> int:
        data = self.read_protocol()
        if len(data) == 2:
            status = struct.unpack("<H", data)[0]
        elif len(data) == 4:
            status = struct.unpack("<I", data)[0]
        elif not data:
            return 0
        else:
            status = struct.unpack_from("<I", data + b"\x00\x00\x00")[0]
        return 0 if status in (0, XFLASH_MAGIC) else status

    def sync(self) -> None:
        self.send_u32(XFLASH_SYNC_SIGNAL)

    def ack(self) -> int:
        self.send_u32(0)
        return self.status()

    def send_param(self, params: bytes | Sequence[bytes]) -> bool:
        if isinstance(params, (bytes, bytearray)):
            params = [bytes(params)]
        for param in params:
            self.send(param)
        return self.status() == 0

    def send_devctrl(self, command: int, param: bytes | None = None) -> bytes:
        """Send a DEVICE_CTRL sub-command.

        The DA expects the ``DEVICE_CTRL`` wrapper first, then the sub-command,
        each followed by its own status.  A command without parameters also
        returns a data packet, followed by a final status packet.
        """

        self.send_u32(XFlashCmd.DEVICE_CTRL)
        status = self.status()
        if status != 0:
            raise ProtocolError(f"DEVICE_CTRL wrapper status 0x{status:08X}")
        self.send_u32(command)
        status = self.status()
        if status != 0:
            raise ProtocolError(f"DEVICE_CTRL 0x{command:08X} status 0x{status:08X}")
        if param is None:
            return self.read_protocol()
        if not self.send_param(param):
            raise ProtocolError(f"DEVICE_CTRL 0x{command:08X} parameter rejected")
        return b""

    def setup_env(self, log_level: int = 2, log_channel: int = 2, system_os: int = 1) -> None:
        self.send_u32(XFlashCmd.SETUP_ENVIRONMENT)
        if not self.send_param(struct.pack("<IIIII", log_level, log_channel, system_os, 0, 0)):
            raise ProtocolError("SETUP_ENVIRONMENT parameters rejected")

    def setup_hw_init(self) -> None:
        self.send_u32(XFlashCmd.SETUP_HW_INIT_PARAMS)
        if not self.send_param(struct.pack("<I", 0)):
            raise ProtocolError("SETUP_HW_INIT_PARAMS parameters rejected")

    def send_emi(self, emi: bytes) -> None:
        self.send_u32(XFlashCmd.INIT_EXT_RAM)
        if self.status() != 0:
            raise ProtocolError("INIT_EXT_RAM rejected")
        time.sleep(0.01)
        self.send_u32(len(emi))
        if not self.send_param(emi):
            raise ProtocolError("EMI/DRAM setup rejected")

    def boot_to(self, address: int, data: bytes, timeout_s: float = 0.5) -> None:
        """Upload a stage and jump to it.

        The XFlash sequence is: ``BOOT_TO`` status, one parameter packet
        (address/length), one data packet, a status for the upload, then the
        stage-2 status after it starts.  Parameter and data packets must not
        have an intervening status read.
        """

        self.send_u32(XFlashCmd.BOOT_TO)
        if self.status() != 0:
            raise ProtocolError("BOOT_TO command rejected")
        self.send(struct.pack("<QQ", address, len(data)))
        self.send(data)
        upload_status = self.status()
        if upload_status != 0:
            raise ProtocolError(f"BOOT_TO upload status 0x{upload_status:08X}")
        time.sleep(max(0.0, timeout_s))
        stage_status = self.status()
        if stage_status not in (0, XFLASH_SYNC_SIGNAL):
            raise ProtocolError(f"BOOT_TO stage status 0x{stage_status:08X}")

    def get_info(self, command: int) -> bytes:
        response = self.send_devctrl(command)
        if not response:
            raise ProtocolError(f"GET info 0x{command:08X} returned no data")
        status = self.status()
        if status != 0:
            raise ProtocolError(f"GET info 0x{command:08X} status 0x{status:08X}")
        return response

    def get_emmc_info(self) -> bytes:
        return self.get_info(XFlashCmd.GET_EMMC_INFO)


# ---------------------------------------------------------------------------
# DA v6 XML
# ---------------------------------------------------------------------------


def _xml_escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def build_xml_command(
    command: str,
    fields: Mapping[str, Any] | None = None,
    version: str = "1.0",
    root_tag: str = "da",
) -> str:
    """Build a DA XML command without allowing caller XML injection."""

    command = command if command.startswith("CMD:") else f"CMD:{command}"
    parts = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f"<{root_tag}>",
        f"<version>{_xml_escape(version)}</version>",
        f"<command>{_xml_escape(command)}</command>",
    ]
    fields = fields or {}
    for key, value in fields.items():
        if isinstance(value, Mapping):
            parts.append(f"<{key}>")
            for child, child_value in value.items():
                parts.append(f"<{child}>{_xml_escape(child_value)}</{child}>")
            parts.append(f"</{key}>")
        elif isinstance(value, (list, tuple)):
            parts.append(f"<{key}>")
            for item in value:
                parts.append(_xml_escape(item))
            parts.append(f"</{key}>")
        else:
            parts.append(f"<{key}>{_xml_escape(value)}</{key}>")
    parts.append(f"</{root_tag}>")
    return "".join(parts)


def _flatten_xml(element: ET.Element, out: dict[str, str]) -> None:
    children = list(element)
    if not children:
        if element.text and element.text.strip():
            out[element.tag] = element.text.strip()
        return
    for child in children:
        _flatten_xml(child, out)


def parse_xml_fields(text: str) -> tuple[str, dict[str, str]]:
    text = text.strip().rstrip("\x00").strip()
    start = text.find("<")
    if start < 0:
        return "", {}
    try:
        root = ET.fromstring(text[start:])
    except ET.ParseError:
        return "", {}
    out: dict[str, str] = {}
    _flatten_xml(root, out)
    command = out.pop("command", "")
    out.pop("version", None)
    return command, out


@dataclass(frozen=True)
class DaFileRequest:
    command: str
    checksum: str = ""
    info: str = ""
    source_file: str = ""
    target_file: str = ""
    packet_length: int = 0x1000
    fields: Mapping[str, str] = field(default_factory=dict)

    @property
    def length(self) -> int | None:
        source = self.source_file or self.target_file
        if not source.startswith("MEM://"):
            return None
        try:
            _address, length = source[6:].split(":", 1)
            return int(length, 16)
        except (ValueError, TypeError):
            return None


@dataclass(frozen=True)
class DaResult:
    command: str
    result: str = ""
    fields: Mapping[str, str] = field(default_factory=dict)
    request: DaFileRequest | None = None
    data: bytes | None = None

    @property
    def ok(self) -> bool:
        if self.command == "CMD:START":
            return True
        return self.result.upper() in ("OK", "START")


class DAXMLProtocol:
    """DA v6 reverse-RPC XML protocol carried over XFlash packets."""

    def __init__(
        self,
        transport: ByteTransport,
        timeout_ms: int = 3000,
        logger: logging.Logger | None = None,
        max_packet: int = 0x1000,
    ) -> None:
        self.transport = transport
        self.timeout_ms = max(50, int(timeout_ms))
        self.log = logger or logging.getLogger("mtk.daxml")
        self.max_packet = max(0x200, int(max_packet))

    # ---- packet plumbing ------------------------------------------------
    def _send_payload(self, payload: bytes) -> None:
        header = struct.pack("<III", XFLASH_MAGIC, DT_PROTOCOL_FLOW, len(payload))
        _write_all(self.transport, header, self.timeout_ms)
        if payload:
            _write_all(self.transport, payload, self.timeout_ms)

    def _read_packet(self) -> XFlashPacket:
        header = _read_exact(self.transport, 12, self.timeout_ms)
        magic, datatype, length = struct.unpack("<III", header)
        if magic != XFLASH_MAGIC:
            raise ProtocolError(f"DA XML bad magic 0x{magic:08X}")
        priority = None
        if datatype == DT_MESSAGE:
            if length < 4:
                raise ProtocolError("DA XML message packet is too short")
            priority = struct.unpack("<I", _read_exact(self.transport, 4, self.timeout_ms))[0]
            length -= 4
        data = _read_exact(self.transport, length, self.timeout_ms) if length else b""
        if datatype == DT_MESSAGE:
            try:
                self.log.debug("[DA] %s", data.rstrip(b"\x00").decode("utf-8", "replace"))
            except Exception:
                pass
        return XFlashPacket(datatype, data, priority)

    def _read_flow_data(self) -> bytes:
        for _ in range(200):
            packet = self._read_packet()
            if packet.datatype == DT_PROTOCOL_FLOW:
                return packet.data
        raise ProtocolError("DA XML: no protocol-flow packet after messages")

    def _read_text(self) -> str:
        return self._read_flow_data().rstrip(b"\x00").decode("utf-8", "replace")

    def send_text(self, text: str) -> None:
        data = text.encode("utf-8")
        if not data.endswith(b"\x00"):
            data += b"\x00"
        self._send_payload(data)

    def send_command(
        self,
        command: str,
        fields: Mapping[str, Any] | None = None,
        version: str = "1.0",
    ) -> DaResult:
        xml = build_xml_command(command, fields, version=version)
        self.send_text(xml)
        response = self._read_text()
        if not response.upper().startswith("OK"):
            # Some DA versions return the command result directly.
            if "CMD:" in response:
                return self._parse_result(response)
            raise DaError(f"DA rejected {command}: {response!r}")
        return self.get_command_result()

    def ack(self) -> None:
        self.send_text("OK")

    def ack_value(self, value: int) -> None:
        self.send_text(f"OK@{hex(value)}")

    def _parse_result(self, text: str, data: bytes | None = None) -> DaResult:
        command, fields = parse_xml_fields(text)
        if command == "CMD:END":
            result = fields.get("result", "")
            return DaResult(command, result, fields, data=data)
        if command in ("CMD:DOWNLOAD-FILE", "CMD:UPLOAD-FILE"):
            try:
                packet_length = int(fields.get("packet_length", "0x1000"), 0)
            except ValueError:
                packet_length = 0x1000
            request = DaFileRequest(
                command=command,
                checksum=fields.get("checksum", ""),
                info=fields.get("info", ""),
                source_file=fields.get("source_file", ""),
                target_file=fields.get("target_file", ""),
                packet_length=packet_length,
                fields=fields,
            )
            return DaResult(command, fields.get("result", ""), fields, request=request, data=data)
        return DaResult(command, fields.get("result", ""), fields, data=data)

    def get_command_result(self) -> DaResult:
        for _ in range(200):
            text = self._read_text()
            command, fields = parse_xml_fields(text)
            if command == "CMD:PROGRESS-REPORT":
                # The DA expects acknowledgements until it sends OK!EOT.
                self.ack()
                while True:
                    report = self._read_text()
                    if report.strip().upper() in ("OK!EOT", "OK!EOT\x00"):
                        break
                    self.ack()
                self.ack()
                continue
            if command == "CMD:START":
                self.ack()
                return DaResult(command, "START", fields)
            if command == "CMD:END":
                result = self._parse_result(text)
                self.ack()
                # An END is usually followed by START for the next operation.
                if result.result.upper() == "OK":
                    try:
                        follow = self.get_command_result()
                        if follow.command == "CMD:START":
                            return follow
                    except (ProtocolError, TransportError):
                        pass
                return result
            if command in ("CMD:DOWNLOAD-FILE", "CMD:UPLOAD-FILE", "CMD:FILE-SYS-OPERATION"):
                result = self._parse_result(text)
                self.ack()
                return result
            if command:
                self.ack()
                return self._parse_result(text)
        raise ProtocolError("too many unsolicited DA XML messages")

    # ---- file transfer --------------------------------------------------
    def upload_file(self, request: DaFileRequest, data: bytes) -> DaResult:
        """Handle a DA ``CMD:DOWNLOAD-FILE`` (DA asks the host to upload)."""

        length = request.length if request.length is not None else len(data)
        if len(data) < length:
            raise DaError(
                f"DA requested {length} bytes but only {len(data)} are available"
            )
        data = data[:length]
        self.ack_value(length)
        response = self._read_text()
        if not response.upper().startswith("OK"):
            raise DaError(f"DA refused upload length: {response!r}")
        packet_length = max(0x200, request.packet_length or 0x1000)
        for pos in range(0, length, packet_length):
            self.ack_value(0)
            response = self._read_text()
            if not response.upper().startswith("OK"):
                raise DaError(f"DA refused upload chunk at 0x{pos:X}: {response!r}")
            self._send_payload(data[pos : pos + packet_length])
            response = self._read_text()
            if not response.upper().startswith("OK"):
                raise DaError(f"DA rejected upload chunk at 0x{pos:X}: {response!r}")
        result = self.get_command_result()
        if not result.ok:
            raise DaError(f"DA upload failed: {result.result}")
        return result

    def download_file(self, request: DaFileRequest) -> bytes:
        """Handle a DA ``CMD:UPLOAD-FILE`` (DA sends a file to the host)."""

        response = self._read_text()
        if not response.upper().startswith("OK@"):
            raise DaError(f"DA did not announce download size: {response!r}")
        try:
            length = int(response.split("@", 1)[1].strip(), 16)
        except ValueError as exc:
            raise DaError(f"invalid download size: {response!r}") from exc
        self.ack()
        response = self._read_text()
        if not response.upper().startswith("OK"):
            raise DaError(f"DA refused download: {response!r}")
        self.ack()
        data = bytearray()
        while len(data) < length:
            data.extend(self._read_flow_data())
        self.ack()
        return bytes(data[:length])

    def boot_to(self, address: int, data: bytes, timeout_s: float = 0.5) -> DaResult:
        source = f"MEM://{hex(address)}:{hex(len(data))}"
        result = self.send_command(
            "BOOT-TO",
            {
                "arg": {
                    "at_address": hex(address),
                    "jmp_address": hex(address),
                    "source_file": source,
                }
            },
        )
        if result.command == "CMD:DOWNLOAD-FILE" and result.request:
            result = self.upload_file(result.request, data)
        time.sleep(max(0.0, timeout_s))
        return result

    def setup_hw_init(self, host_info: str = "") -> DaResult:
        result = self.send_command(
            "HOST-SUPPORTED-COMMANDS",
            {
                "arg": {
                    "host_capability": (
                        "CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1@"
                        "CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@"
                    )
                }
            },
        )
        if not result.ok:
            raise DaError(f"HOST-SUPPORTED-COMMANDS failed: {result.result}")
        result = self.send_command("NOTIFY-INIT-HW")
        if not result.ok:
            raise DaError(f"NOTIFY-INIT-HW failed: {result.result}")
        # Older DA builds may not implement SET-HOST-INFO; it is advisory.
        try:
            self.send_command(
                "SET-HOST-INFO",
                {"arg": {"info": host_info or time.strftime("%Y%m%dT%H%M%S")}},
            )
        except (DaError, ProtocolError, TransportError):
            pass
        return result

    def setup(self, log_level: str = "INFO", log_channel: str = "USB") -> DaResult:
        result = self.send_command(
            "SET-RUNTIME-PARAMETER",
            {
                "arg": {
                    "checksum_level": "NONE",
                    "battery_exist": "AUTO-DETECT",
                    "da_log_level": log_level,
                    "log_channel": log_channel,
                    "system_os": "LINUX",
                },
                "adv": {"initialize_dram": "YES"},
            },
            version="1.1",
        )
        if not result.ok:
            raise DaError(f"SET-RUNTIME-PARAMETER failed: {result.result}")
        return self.setup_hw_init()

    def security_set_flash_policy(self, data: bytes, address: int = 0x8000000) -> DaResult:
        source = f"MEM://{hex(address)}:{hex(len(data))}"
        result = self.send_command(
            "SECURITY-SET-FLASH-POLICY", {"arg": {"source_file": source}}
        )
        if result.command == "CMD:DOWNLOAD-FILE" and result.request:
            return self.upload_file(result.request, data)
        return result

    def read_flash(self, address: int, length: int) -> bytes:
        source = f"MEM://{hex(address)}:{hex(length)}"
        result = self.send_command(
            "READ-FLASH", {"arg": {"source_file": source}}
        )
        if result.command == "CMD:UPLOAD-FILE" and result.request:
            return self.download_file(result.request)
        raise DaError(f"READ-FLASH did not return an UPLOAD-FILE request: {result.command}")


__all__ = [
    "BROM_SYNC",
    "BROM_SYNC_RESPONSE",
    "BromAuthResult",
    "BromProtocol",
    "ByteTransport",
    "DAXMLProtocol",
    "DaFileRequest",
    "DaResult",
    "DT_MESSAGE",
    "DT_PROTOCOL_FLOW",
    "HwCode",
    "TargetConfig",
    "XFLASH_MAGIC",
    "XFlashCmd",
    "XFlashPacket",
    "XFlashV5",
    "build_xml_command",
    "parse_xml_fields",
]
