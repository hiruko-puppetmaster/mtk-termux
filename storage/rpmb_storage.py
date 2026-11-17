"""eMMC RPMB framing, authentication and provisioning.

RPMB frames are exactly 512 bytes in the JEDEC eMMC layout used by the Linux
kernel:

    stuff[196] key_or_mac[32] data[256] nonce[16]
    write_counter[4] address[2] block_count[2] result[2] req_resp[2]

All integer fields are big-endian.  Authenticated requests use
HMAC-SHA-256 over the complete frame with the key/MAC field zeroed; the MAC is
then stored in the key/MAC field.  AUTH_READ responses are verified with the
same rules.

Provisioning an RPMB key is irreversible.  ``RpmbManager.program_key`` refuses
to run unless ``confirm=True`` is explicitly supplied.  DA2 firmware exposes
RPMB through a vendor extension; this module therefore talks to an abstract
``RpmbBackend`` and includes a ``DA2RpmbBackend`` adapter for a custom DA2
opcode.  Stock DA2 loaders do not necessarily implement that opcode.

The implementation is intentionally dependency-free (stdlib only) so it works
inside Termux without cryptography wheels.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Protocol, runtime_checkable

from core.errors import RpmbError

FRAME_SIZE = 512
STUFF_SIZE = 196
KEY_MAC_SIZE = 32
DATA_SIZE = 256
NONCE_SIZE = 16
BLOCK_SIZE = 256
MAX_BLOCKS = 0x100

OFF_KEY_MAC = 196
OFF_DATA = 228
OFF_NONCE = 484
OFF_WRITE_COUNTER = 500
OFF_ADDRESS = 504
OFF_BLOCK_COUNT = 506
OFF_RESULT = 508
OFF_REQ_RESP = 510


class RpmbRequest(IntEnum):
    PROGRAM_KEY = 0x0001
    GET_WRITE_COUNTER = 0x0002
    AUTH_WRITE = 0x0003
    AUTH_READ = 0x0004
    RESULT_READ = 0x0005


class RpmbResponse(IntEnum):
    PROGRAM_KEY = 0x0100
    GET_WRITE_COUNTER = 0x0200
    AUTH_WRITE = 0x0300
    AUTH_READ = 0x0400
    RESULT_READ = 0x0500


class RpmbResult(IntEnum):
    SUCCESS = 0x0000
    GENERAL_FAILURE = 0x0001
    AUTH_FAILURE = 0x0002
    WRITE_COUNTER_FAILURE = 0x0003
    ADDRESS_FAILURE = 0x0004
    WRITE_FAILURE = 0x0005
    READ_FAILURE = 0x0006
    KEY_NOT_PROGRAMMED = 0x0007
    INVALID_KEY = 0x0008


_RESULT_MESSAGES = {
    0x0000: "success",
    0x0001: "general failure",
    0x0002: "authentication failure",
    0x0003: "write counter expired or invalid",
    0x0004: "address failure",
    0x0005: "write failure",
    0x0006: "read failure",
    0x0007: "RPMB key is not programmed",
    0x0008: "invalid key",
}


def result_message(code: int) -> str:
    return _RESULT_MESSAGES.get(code, f"unknown RPMB result 0x{code:04X}")


@dataclass
class RpmbFrame:
    key_mac: bytes = b"\x00" * KEY_MAC_SIZE
    data: bytes = b"\x00" * DATA_SIZE
    nonce: bytes = b"\x00" * NONCE_SIZE
    write_counter: int = 0
    address: int = 0
    block_count: int = 0
    result: int = 0
    req_resp: int = 0
    stuff: bytes = b"\x00" * STUFF_SIZE

    def __post_init__(self) -> None:
        if len(self.key_mac) != KEY_MAC_SIZE:
            raise ValueError("key_mac must be 32 bytes")
        if len(self.data) != DATA_SIZE:
            raise ValueError("data must be 256 bytes")
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError("nonce must be 16 bytes")
        if len(self.stuff) != STUFF_SIZE:
            raise ValueError("stuff must be 196 bytes")
        if not (0 <= self.write_counter <= 0xFFFFFFFF):
            raise ValueError("write_counter out of range")
        if not (0 <= self.address <= 0xFFFF):
            raise ValueError("address out of range")
        if not (0 <= self.block_count <= 0xFFFF):
            raise ValueError("block_count out of range")
        if not (0 <= self.result <= 0xFFFF):
            raise ValueError("result out of range")
        if not (0 <= self.req_resp <= 0xFFFF):
            raise ValueError("req_resp out of range")

    @classmethod
    def unpack(cls, raw: bytes) -> "RpmbFrame":
        if len(raw) != FRAME_SIZE:
            raise RpmbError(f"RPMB frame must be {FRAME_SIZE} bytes, got {len(raw)}")
        return cls(
            stuff=raw[0:OFF_KEY_MAC],
            key_mac=raw[OFF_KEY_MAC:OFF_DATA],
            data=raw[OFF_DATA:OFF_NONCE],
            nonce=raw[OFF_NONCE:OFF_WRITE_COUNTER],
            write_counter=struct.unpack_from(">I", raw, OFF_WRITE_COUNTER)[0],
            address=struct.unpack_from(">H", raw, OFF_ADDRESS)[0],
            block_count=struct.unpack_from(">H", raw, OFF_BLOCK_COUNT)[0],
            result=struct.unpack_from(">H", raw, OFF_RESULT)[0],
            req_resp=struct.unpack_from(">H", raw, OFF_REQ_RESP)[0],
        )

    def pack(self) -> bytes:
        raw = bytearray(FRAME_SIZE)
        raw[0:OFF_KEY_MAC] = self.stuff
        raw[OFF_KEY_MAC:OFF_DATA] = self.key_mac
        raw[OFF_DATA:OFF_NONCE] = self.data
        raw[OFF_NONCE:OFF_WRITE_COUNTER] = self.nonce
        struct.pack_into(">I", raw, OFF_WRITE_COUNTER, self.write_counter)
        struct.pack_into(">H", raw, OFF_ADDRESS, self.address)
        struct.pack_into(">H", raw, OFF_BLOCK_COUNT, self.block_count)
        struct.pack_into(">H", raw, OFF_RESULT, self.result)
        struct.pack_into(">H", raw, OFF_REQ_RESP, self.req_resp)
        return bytes(raw)

    def compute_mac(self, key: bytes) -> bytes:
        if len(key) != 32:
            raise RpmbError("RPMB key must be 32 bytes")
        unsigned = bytearray(self.pack())
        unsigned[OFF_KEY_MAC:OFF_DATA] = b"\x00" * KEY_MAC_SIZE
        return hmac.new(key, bytes(unsigned), hashlib.sha256).digest()

    def sign(self, key: bytes) -> "RpmbFrame":
        self.key_mac = self.compute_mac(key)
        return self

    def verify(self, key: bytes) -> bool:
        expected = self.compute_mac(key)
        return hmac.compare_digest(expected, self.key_mac)

    @property
    def request_type(self) -> int:
        return self.req_resp

    @property
    def response_type(self) -> int:
        return self.req_resp

    def is_response_to(self, request: RpmbRequest) -> bool:
        return self.req_resp == (int(request) << 8)

    def require_success(self) -> None:
        if self.result != RpmbResult.SUCCESS:
            raise RpmbError(
                f"RPMB request 0x{self.req_resp:04X} failed: "
                f"{result_message(self.result)} (0x{self.result:04X})"
            )


@runtime_checkable
class RpmbBackend(Protocol):
    """Transport that sends a 512-byte RPMB frame and returns the response."""

    def transmit(self, frame: bytes) -> bytes: ...


class RpmbManager:
    """High-level authenticated RPMB operations."""

    def __init__(self, backend: RpmbBackend, key: bytes | None = None) -> None:
        if key is not None and len(key) != 32:
            raise ValueError("RPMB key must be 32 bytes")
        self.backend = backend
        self.key = key

    def _transmit(self, frame: RpmbFrame) -> RpmbFrame:
        try:
            raw = self.backend.transmit(frame.pack())
        except RpmbError:
            raise
        except Exception as exc:
            raise RpmbError(f"RPMB transport failed: {exc}") from exc
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != FRAME_SIZE:
            raise RpmbError(
                f"RPMB transport returned {len(raw) if raw is not None else 0} "
                f"bytes, expected {FRAME_SIZE}"
            )
        return RpmbFrame.unpack(bytes(raw))

    def get_write_counter(self) -> int:
        frame = RpmbFrame(
            nonce=os.urandom(NONCE_SIZE),
            req_resp=int(RpmbRequest.GET_WRITE_COUNTER),
        )
        response = self._transmit(frame)
        if response.req_resp not in (
            int(RpmbResponse.GET_WRITE_COUNTER),
            int(RpmbRequest.GET_WRITE_COUNTER),
        ):
            raise RpmbError(
                f"unexpected RPMB response type 0x{response.req_resp:04X}"
            )
        response.require_success()
        if response.nonce != frame.nonce:
            raise RpmbError("RPMB write-counter nonce mismatch")
        return response.write_counter

    def program_key(self, key: bytes | None = None, *, confirm: bool = False) -> None:
        key = key or self.key
        if key is None or len(key) != 32:
            raise RpmbError("a 32-byte RPMB key is required")
        if not confirm:
            raise RpmbError(
                "RPMB key programming is irreversible; pass confirm=True only "
                "after verifying the key and the target eMMC"
            )
        frame = RpmbFrame(
            key_mac=key,
            req_resp=int(RpmbRequest.PROGRAM_KEY),
        )
        response = self._transmit(frame)
        if response.req_resp not in (
            int(RpmbResponse.PROGRAM_KEY),
            int(RpmbRequest.PROGRAM_KEY),
        ):
            raise RpmbError(
                f"unexpected RPMB key-program response 0x{response.req_resp:04X}"
            )
        response.require_success()
        self.key = key

    def provision_key(self, key: bytes, *, confirm: bool = False) -> None:
        self.program_key(key, confirm=confirm)

    def _read_one(
        self,
        address: int,
        key: bytes,
        nonce: bytes,
    ) -> bytes:
        frame = RpmbFrame(
            nonce=nonce,
            address=address,
            block_count=1,
            req_resp=int(RpmbRequest.AUTH_READ),
        )
        frame.sign(key)
        response = self._transmit(frame)
        if not response.is_response_to(RpmbRequest.AUTH_READ):
            raise RpmbError(
                f"unexpected RPMB read response type 0x{response.req_resp:04X}"
            )
        response.require_success()
        if response.nonce != nonce:
            raise RpmbError("RPMB read nonce mismatch")
        # JEDEC response frames commonly leave address/block-count at zero;
        # accept either the echoed request or zero, but reject a different
        # address/count.
        if response.address not in (0, address) or response.block_count not in (0, 1):
            raise RpmbError("RPMB read response address/count mismatch")
        if not response.verify(key):
            raise RpmbError("RPMB read response MAC verification failed")
        return response.data[:BLOCK_SIZE]

    def read_blocks(
        self,
        address: int,
        count: int = 1,
        key: bytes | None = None,
        nonce: bytes | None = None,
    ) -> bytes:
        """Read ``count`` RPMB blocks.

        The JEDEC frame carries a single 256-byte data block, so a multi-block
        read is issued as one authenticated request per address.  ``address``
        counts 256-byte blocks, not 512-byte frames.
        """

        key = key or self.key
        if key is None or len(key) != 32:
            raise RpmbError("a 32-byte RPMB key is required for authenticated read")
        if count < 1 or count > MAX_BLOCKS:
            raise RpmbError(f"block count must be 1..{MAX_BLOCKS}")
        if address < 0 or address + count > 0x10000:
            raise RpmbError("RPMB address range exceeds the 16-bit block address")
        chunks = []
        for offset in range(count):
            chunk_nonce = nonce if nonce is not None else os.urandom(NONCE_SIZE)
            chunks.append(self._read_one(address + offset, key, chunk_nonce))
        return b"".join(chunks)

    def _write_one(
        self,
        address: int,
        block: bytes,
        key: bytes,
        counter: int,
        nonce: bytes,
    ) -> None:
        frame = RpmbFrame(
            data=block,
            nonce=nonce,
            write_counter=counter,
            address=address,
            block_count=1,
            req_resp=int(RpmbRequest.AUTH_WRITE),
        )
        frame.sign(key)
        response = self._transmit(frame)
        if not response.is_response_to(RpmbRequest.AUTH_WRITE):
            raise RpmbError(
                f"unexpected RPMB write response type 0x{response.req_resp:04X}"
            )
        response.require_success()
        if response.nonce != nonce:
            raise RpmbError("RPMB write response nonce mismatch")
        if not response.verify(key):
            raise RpmbError("RPMB write response MAC verification failed")

    def write_blocks(
        self,
        address: int,
        data: bytes,
        key: bytes | None = None,
        nonce: bytes | None = None,
    ) -> int:
        """Write ``data`` as consecutive 256-byte RPMB blocks.

        Returns the next write counter value.  Each block is a separate
        authenticated request and consumes one write-counter tick.
        """

        key = key or self.key
        if key is None or len(key) != 32:
            raise RpmbError("a 32-byte RPMB key is required for authenticated write")
        if not data or len(data) % BLOCK_SIZE:
            raise RpmbError(
                f"RPMB write data must be a non-empty multiple of {BLOCK_SIZE} bytes"
            )
        count = len(data) // BLOCK_SIZE
        if count > MAX_BLOCKS:
            raise RpmbError(f"a single RPMB write may not exceed {MAX_BLOCKS} blocks")
        if address < 0 or address + count > 0x10000:
            raise RpmbError("RPMB address range exceeds the 16-bit block address")
        counter = self.get_write_counter()
        for offset in range(count):
            block = data[offset * BLOCK_SIZE : (offset + 1) * BLOCK_SIZE]
            block_nonce = nonce if nonce is not None else os.urandom(NONCE_SIZE)
            self._write_one(address + offset, block, key, counter, block_nonce)
            counter = (counter + 1) & 0xFFFFFFFF
        return counter

    def read(self, address: int, count: int = 1, **kwargs) -> bytes:
        return self.read_blocks(address, count, **kwargs)

    def write(self, address: int, data: bytes, **kwargs) -> int:
        return self.write_blocks(address, data, **kwargs)


class DA2RpmbBackend:
    """RPMB frame transport over a DA2 custom extension opcode.

    The vendor DA2 must implement a command that accepts one 512-byte RPMB
    frame and returns one 512-byte response frame.  ``opcode`` is configurable
    because different DA builds use different extension numbers.  If the loader
    does not expose such an opcode, use a different ``RpmbBackend``.
    """

    DEFAULT_OPCODE = 0x0F000B

    def __init__(self, xflash, opcode: int = DEFAULT_OPCODE) -> None:
        self.xflash = xflash
        self.opcode = opcode

    def transmit(self, frame: bytes) -> bytes:
        if len(frame) != FRAME_SIZE:
            raise RpmbError(f"RPMB frame must be {FRAME_SIZE} bytes")
        x = self.xflash
        # The extension speaks the same XFlash framing as other DA commands.
        x.send_u32(self.opcode)
        status = x.status()
        if status != 0:
            raise RpmbError(f"DA2 RPMB opcode 0x{self.opcode:08X} rejected: 0x{status:08X}")
        if not x.send_param(frame):
            raise RpmbError("DA2 rejected the RPMB frame")
        response = x.read_protocol()
        if len(response) != FRAME_SIZE:
            raise RpmbError(
                f"DA2 returned {len(response)} bytes for RPMB, expected {FRAME_SIZE}"
            )
        return response


__all__ = [
    "DA2RpmbBackend",
    "FRAME_SIZE",
    "MAX_BLOCKS",
    "RpmbBackend",
    "RpmbError",
    "RpmbFrame",
    "RpmbManager",
    "RpmbRequest",
    "RpmbResponse",
    "RpmbResult",
    "result_message",
]
