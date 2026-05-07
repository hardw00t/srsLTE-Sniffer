"""Append-only crash-safe capture journal.

Replaces the original `payload.txt` "last payload" file with a journal that
survives crashes and lets you replay captures offline through the analyzer.

Format: one length-prefixed record per write, fsync'd on every flush.

    [u32 magic 0x53524C53] [u32 version=1] [u8 kind] [u64 ts_us]
    [u32 payload_len] [payload bytes]

Reading is forward-only and tolerant of trailing torn writes (truncated final
record is dropped silently — that's the expected behaviour after a crash mid
write).
"""

from __future__ import annotations

import contextlib
import struct
import time
from collections.abc import Iterator
from pathlib import Path

MAGIC = 0x53524C53  # 'SRLS'
VERSION = 1

KIND_PCCH = 1
KIND_SIB1 = 2
KIND_SIB2 = 3
KIND_OTHER = 9

_HEADER = struct.Struct("<IIBQI")  # magic, ver, kind, ts_us, payload_len


class Journal:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh = self.path.open("ab")

    def write(self, payload: bytes, *, kind: int = KIND_PCCH,
              ts_us: int | None = None, fsync: bool = True) -> None:
        if ts_us is None:
            ts_us = int(time.time() * 1e6)
        self._fh.write(_HEADER.pack(MAGIC, VERSION, kind, ts_us, len(payload)))
        self._fh.write(payload)
        self._fh.flush()
        if fsync:
            import os
            os.fsync(self._fh.fileno())

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self._fh.close()

    def __enter__(self) -> Journal:
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def replay(path: str | Path) -> Iterator[tuple[int, int, bytes]]:
    """Yield (kind, ts_us, payload) tuples. Drops the trailing torn record."""
    p = Path(path)
    if not p.exists():
        return
    with p.open("rb") as fh:
        while True:
            head = fh.read(_HEADER.size)
            if len(head) < _HEADER.size:
                return
            magic, ver, kind, ts_us, plen = _HEADER.unpack(head)
            if magic != MAGIC:
                # Corrupt journal — bail rather than guessing.
                return
            if ver != VERSION:
                return
            payload = fh.read(plen)
            if len(payload) < plen:
                return  # torn write — drop
            yield kind, ts_us, payload
