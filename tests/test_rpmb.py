from __future__ import annotations

import os
import unittest

from storage.rpmb_storage import (
    BLOCK_SIZE,
    FRAME_SIZE,
    RpmbFrame,
    RpmbManager,
    RpmbRequest,
    RpmbResponse,
    RpmbResult,
)


class MemoryRpmbBackend:
    def __init__(self) -> None:
        self.key: bytes | None = None
        self.counter = 7
        self.blocks: dict[int, bytes] = {}

    def _response(self, request: RpmbRequest, *, nonce=b"\x00" * 16, data=b"\x00" * 256, address=0, count=0, result=0) -> bytes:
        frame = RpmbFrame(
            data=data,
            nonce=nonce,
            write_counter=self.counter,
            address=address,
            block_count=count,
            result=result,
            req_resp=request << 8,
        )
        if self.key:
            frame.sign(self.key)
        return frame.pack()

    def transmit(self, raw: bytes) -> bytes:
        frame = RpmbFrame.unpack(raw)
        if frame.req_resp == RpmbRequest.PROGRAM_KEY:
            if self.key is not None:
                return self._response(RpmbRequest.PROGRAM_KEY, result=RpmbResult.GENERAL_FAILURE)
            self.key = frame.key_mac
            return self._response(RpmbRequest.PROGRAM_KEY)
        if frame.req_resp == RpmbRequest.GET_WRITE_COUNTER:
            return self._response(
                RpmbRequest.GET_WRITE_COUNTER, nonce=frame.nonce
            )
        if frame.req_resp == RpmbRequest.AUTH_WRITE:
            if not self.key or not frame.verify(self.key):
                return self._response(
                    RpmbRequest.AUTH_WRITE,
                    nonce=frame.nonce,
                    address=frame.address,
                    count=frame.block_count,
                    result=RpmbResult.AUTH_FAILURE,
                )
            if frame.block_count != 1:
                return self._response(
                    RpmbRequest.AUTH_WRITE,
                    nonce=frame.nonce,
                    address=frame.address,
                    count=frame.block_count,
                    result=RpmbResult.GENERAL_FAILURE,
                )
            if frame.write_counter != self.counter:
                return self._response(
                    RpmbRequest.AUTH_WRITE,
                    nonce=frame.nonce,
                    address=frame.address,
                    count=frame.block_count,
                    result=RpmbResult.WRITE_COUNTER_FAILURE,
                )
            self.blocks[frame.address] = frame.data[:BLOCK_SIZE]
            self.counter += 1
            return self._response(
                RpmbRequest.AUTH_WRITE,
                nonce=frame.nonce,
                address=frame.address,
                count=frame.block_count,
            )
        if frame.req_resp == RpmbRequest.AUTH_READ:
            if not self.key or not frame.verify(self.key):
                return self._response(
                    RpmbRequest.AUTH_READ,
                    nonce=frame.nonce,
                    address=frame.address,
                    count=frame.block_count,
                    result=RpmbResult.AUTH_FAILURE,
                )
            if frame.block_count != 1:
                return self._response(
                    RpmbRequest.AUTH_READ,
                    nonce=frame.nonce,
                    address=frame.address,
                    count=frame.block_count,
                    result=RpmbResult.GENERAL_FAILURE,
                )
            data = self.blocks.get(frame.address, b"\x00" * BLOCK_SIZE)
            return self._response(
                RpmbRequest.AUTH_READ,
                nonce=frame.nonce,
                data=data.ljust(256, b"\x00"),
                # Real eMMC response frames normally leave these fields zero.
                address=0,
                count=0,
            )
        return self._response(RpmbRequest.RESULT_READ, result=RpmbResult.GENERAL_FAILURE)


class RpmbTests(unittest.TestCase):
    def test_frame_roundtrip(self):
        frame = RpmbFrame(
            data=b"D" * 256,
            nonce=b"N" * 16,
            write_counter=0x11223344,
            address=0x55AA,
            block_count=1,
            result=0,
            req_resp=int(RpmbRequest.AUTH_WRITE),
        )
        raw = frame.pack()
        self.assertEqual(len(raw), FRAME_SIZE)
        parsed = RpmbFrame.unpack(raw)
        self.assertEqual(parsed.write_counter, 0x11223344)
        self.assertEqual(parsed.address, 0x55AA)
        self.assertEqual(parsed.data, b"D" * 256)
        self.assertEqual(parsed.req_resp, 3)

    def test_program_key_requires_confirmation(self):
        backend = MemoryRpmbBackend()
        manager = RpmbManager(backend, key=b"K" * 32)
        with self.assertRaises(Exception):
            manager.program_key(b"K" * 32)
        manager.program_key(b"K" * 32, confirm=True)
        self.assertEqual(backend.key, b"K" * 32)
        # A second programming attempt must fail.
        with self.assertRaises(Exception):
            manager.program_key(b"K" * 32, confirm=True)

    def test_write_and_read(self):
        backend = MemoryRpmbBackend()
        manager = RpmbManager(backend, key=b"Z" * 32)
        manager.program_key(b"Z" * 32, confirm=True)
        data = b"hello rpmb".ljust(BLOCK_SIZE, b"\x00")
        new_counter = manager.write_blocks(3, data)
        self.assertEqual(new_counter, backend.counter)
        self.assertEqual(manager.read_blocks(3), data)
        self.assertEqual(manager.get_write_counter(), backend.counter)

    def test_multi_block_write_and_read(self):
        backend = MemoryRpmbBackend()
        manager = RpmbManager(backend, key=b"M" * 32)
        manager.program_key(b"M" * 32, confirm=True)
        blocks = [bytes([i]) * BLOCK_SIZE for i in range(1, 5)]
        start_counter = backend.counter
        end_counter = manager.write_blocks(0x20, b"".join(blocks))
        self.assertEqual(end_counter, start_counter + len(blocks))
        self.assertEqual(backend.counter, end_counter)
        self.assertEqual(manager.read_blocks(0x20, len(blocks)), b"".join(blocks))
        self.assertEqual(backend.blocks[0x21], blocks[1])

    def test_block_limits(self):
        backend = MemoryRpmbBackend()
        manager = RpmbManager(backend, key=b"L" * 32)
        manager.program_key(b"L" * 32, confirm=True)
        with self.assertRaises(Exception):
            manager.read_blocks(0, 0)
        with self.assertRaises(Exception):
            manager.write_blocks(0, b"x" * (BLOCK_SIZE + 1))
        with self.assertRaises(Exception):
            manager.write_blocks(0xFFFF, b"x" * (BLOCK_SIZE * 2))

    def test_mac_tamper(self):
        frame = RpmbFrame(
            data=b"x" * 256,
            nonce=os.urandom(16),
            address=0,
            block_count=1,
            req_resp=int(RpmbRequest.AUTH_READ),
        )
        frame.sign(b"Q" * 32)
        raw = bytearray(frame.pack())
        raw[-1] ^= 1
        parsed = RpmbFrame.unpack(bytes(raw))
        self.assertFalse(parsed.verify(b"Q" * 32))


if __name__ == "__main__":
    unittest.main()
