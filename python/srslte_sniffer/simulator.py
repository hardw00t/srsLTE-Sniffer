"""Capture replay simulator.

Drives the streaming pipeline end-to-end without an SDR by re-writing a
recorded capture into a journal at a configurable cadence. Two uses:

1. **Local development** — run the dashboard against a journal that's being
   "captured" right now from a saved pcap. Indistinguishable from the real
   thing as far as the analyzer is concerned.

2. **HIL test** — gives integration tests deterministic input. The lab
   eNB stack (srsenb + srsue) in `tests/hil/docker-compose.yml` is the
   real ground-truth path; the simulator is the offline path that runs
   in CI without docker.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterable
from pathlib import Path

from .journal import KIND_PCCH, KIND_SIB1, KIND_SIB2, Journal
from .pcap_io import CapturedFrame, read_capture


def _journal_kind(framing: str) -> int:
    if framing == "pcch":
        return KIND_PCCH
    if framing == "sib1":
        return KIND_SIB1
    if framing == "sib2":
        return KIND_SIB2
    return KIND_PCCH  # default — analyser will sort out unknowns by decode


async def replay_into_journal(
    capture_path: str | Path,
    journal_path: str | Path,
    *,
    rate_hz: float = 100.0,
    limit: int | None = None,
) -> int:
    """Read a capture file and append each frame to ``journal_path`` at
    ``rate_hz`` records per second. Returns the number of records written.

    Setting ``rate_hz=0`` disables sleeping (write as fast as possible).
    """
    delay = 1.0 / rate_hz if rate_hz > 0 else 0.0
    n = 0
    journal = Journal(journal_path)
    try:
        for frame in read_capture(str(capture_path)):
            journal.write(
                frame.payload,
                kind=_journal_kind(frame.framing),
                ts_us=int(time.time() * 1e6),
                fsync=False,  # batch fsync via close — much faster
            )
            n += 1
            if limit is not None and n >= limit:
                break
            if delay:
                await asyncio.sleep(delay)
    finally:
        journal.close()
    return n


def replay_sync(
    capture_path: str | Path,
    journal_path: str | Path,
    *,
    rate_hz: float = 0.0,
    limit: int | None = None,
) -> int:
    """Synchronous variant — used by tests that don't want an event loop."""
    delay = 1.0 / rate_hz if rate_hz > 0 else 0.0
    n = 0
    journal = Journal(journal_path)
    try:
        for frame in read_capture(str(capture_path)):
            journal.write(
                frame.payload,
                kind=_journal_kind(frame.framing),
                ts_us=int(time.time() * 1e6),
                fsync=False,
            )
            n += 1
            if limit is not None and n >= limit:
                break
            if delay:
                time.sleep(delay)
    finally:
        journal.close()
    return n


def frames_from_capture(path: str | Path) -> Iterable[CapturedFrame]:
    """Convenience re-export so tests can grab raw frames."""
    return read_capture(str(path))
