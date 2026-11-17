"""Small fakes shared by the unit tests."""

from __future__ import annotations

from typing import Iterable


class FakeTransport:
    def __init__(self, reads: bytes = b"") -> None:
        self.read_buffer = bytearray(reads)
        self.writes = bytearray()
        self.ctrl: list[tuple] = []
        self.flushes = 0
        self.zero_writes = 0

    def write(self, data: bytes, timeout_ms: int | None = None) -> int:
        if not data:
            self.zero_writes += 1
        self.writes.extend(data)
        return len(data)

    def read(self, size: int, timeout_ms: int | None = None) -> bytes:
        if not self.read_buffer:
            return b""
        chunk = bytes(self.read_buffer[:size])
        del self.read_buffer[:size]
        return chunk

    def read_exact(self, size: int, timeout_ms: int | None = None) -> bytes:
        if len(self.read_buffer) < size:
            raise AssertionError(
                f"FakeTransport underrun: need {size}, have {len(self.read_buffer)}"
            )
        data = bytes(self.read_buffer[:size])
        del self.read_buffer[:size]
        return data

    def flush(self, timeout_ms: int = 50) -> None:
        self.flushes += 1

    def ctrl_transfer(self, *args, **kwargs) -> bytes:
        self.ctrl.append((args, kwargs))
        return b""

    def close(self) -> None:
        pass
