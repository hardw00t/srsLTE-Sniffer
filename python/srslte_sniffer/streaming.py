"""Async journal tail + streaming decode pipeline.

The original `Journal.replay()` is a finite generator — opens, reads to EOF,
returns. For real-time observability we need to *follow* a journal as the
sniffer writes to it, decode each record as it lands, and fan the result
out to subscribers (the WebSocket dashboard, Prometheus exporter, webhook
alerter).

This module is intentionally pure-Python asyncio (no inotify) so it works
on any platform — we poll the file size with a small sleep when at EOF. On
Linux a future optimisation could use `inotify` to skip the poll, but the
overhead at 5 ms cadence is negligible compared to pycrate decode time.

Public API:

    async for event in stream_journal(path):
        ...

    pipeline = StreamingPipeline(journal_path, decoder_workers=4)
    pipeline.subscribe(my_callback)
    await pipeline.run()
"""

from __future__ import annotations

import asyncio
import dataclasses
import struct
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import aiofiles

from .decoder import (
    PagingRecord,
    decode_pcch,
    extract_paging_records,
)
from .journal import KIND_PCCH, MAGIC, VERSION

_HEADER_FMT = "<IIBQI"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)


@dataclasses.dataclass
class StreamEvent:
    """A decoded record with its provenance."""

    kind: int  # KIND_PCCH / KIND_SIB1 / KIND_SIB2
    ts_us: int
    raw: bytes
    records: list[PagingRecord]
    decode_ok: bool
    error: str | None = None


async def _read_exact(fh, n: int) -> bytes | None:
    """Read exactly n bytes, returning None if the file ends short.
    Caller is expected to retry after sleeping for new data."""
    buf = await fh.read(n)
    if len(buf) < n:
        # Rewind so the next read sees the partial bytes again.
        await fh.seek(-len(buf), 1)
        return None
    return buf


async def stream_journal(
    path: str | Path,
    *,
    poll_interval_s: float = 0.05,
    follow: bool = True,
    stop_event: asyncio.Event | None = None,
) -> AsyncIterator[tuple[int, int, bytes]]:
    """Yield (kind, ts_us, payload) tuples. With ``follow=True`` (the default)
    blocks at EOF and re-checks until ``stop_event`` is set.

    Tolerates torn writes the same way ``journal.replay`` does — a partially
    written record at the tail is retried until it's complete.
    """
    p = Path(path)
    # Wait for the file to exist if the writer hasn't started yet.
    while not p.exists():
        if stop_event and stop_event.is_set():
            return
        await asyncio.sleep(poll_interval_s)

    async with aiofiles.open(p, "rb") as fh:
        while True:
            if stop_event and stop_event.is_set():
                return
            head = await _read_exact(fh, _HEADER_SIZE)
            if head is None:
                if not follow:
                    return
                await asyncio.sleep(poll_interval_s)
                continue
            magic, ver, kind, ts_us, plen = struct.unpack(_HEADER_FMT, head)
            if magic != MAGIC or ver != VERSION:
                # Corrupt — there's no safe way to resync, so bail.
                return
            payload = await _read_exact(fh, plen)
            if payload is None:
                # Header landed but body hasn't yet; retry.
                if not follow:
                    return
                # Rewind the header too so we re-read the whole record.
                await fh.seek(-_HEADER_SIZE, 1)
                await asyncio.sleep(poll_interval_s)
                continue
            yield kind, ts_us, payload


class StreamingPipeline:
    """Glue: tail a journal → decode pool → fan-out to subscribers.

    Backpressure: bounded queue. When full, oldest events are dropped and
    the drop counter is incremented (exposed as a metric).
    """

    def __init__(
        self,
        journal_path: str | Path,
        *,
        decoder_workers: int = 2,
        queue_size: int = 1024,
    ) -> None:
        self.journal_path = Path(journal_path)
        self.decoder_workers = decoder_workers
        self._raw_q: asyncio.Queue[tuple[int, int, bytes]] = asyncio.Queue(
            queue_size
        )
        self._event_q: asyncio.Queue[StreamEvent] = asyncio.Queue(queue_size)
        self._subscribers: list[Callable[[StreamEvent], None]] = []
        self._stop = asyncio.Event()
        self.dropped = 0
        self.processed = 0

    def subscribe(self, callback: Callable[[StreamEvent], None]) -> None:
        self._subscribers.append(callback)

    def stop(self) -> None:
        self._stop.set()

    async def _ingest_task(self) -> None:
        async for kind, ts, payload in stream_journal(
            self.journal_path, stop_event=self._stop
        ):
            try:
                self._raw_q.put_nowait((kind, ts, payload))
            except asyncio.QueueFull:
                self.dropped += 1
                # Drop oldest, push newest.
                try:
                    self._raw_q.get_nowait()
                    self._raw_q.put_nowait((kind, ts, payload))
                except asyncio.QueueEmpty:
                    pass

    async def _decode_worker(self) -> None:
        while not self._stop.is_set():
            try:
                kind, ts, payload = await asyncio.wait_for(
                    self._raw_q.get(), timeout=0.25
                )
            except asyncio.TimeoutError:
                continue
            event = self._decode_one(kind, ts, payload)
            self.processed += 1
            try:
                self._event_q.put_nowait(event)
            except asyncio.QueueFull:
                self.dropped += 1

    @staticmethod
    def _decode_one(kind: int, ts: int, payload: bytes) -> StreamEvent:
        if kind == KIND_PCCH:
            res = decode_pcch(payload)
            return StreamEvent(
                kind=kind, ts_us=ts, raw=payload,
                records=extract_paging_records(res) if res.ok else [],
                decode_ok=res.ok, error=res.error,
            )
        # SIB framings — return raw, decoder-side per-SIB carving runs in the
        # batch analyzer; live dashboard mainly cares about pagings.
        return StreamEvent(
            kind=kind, ts_us=ts, raw=payload,
            records=[], decode_ok=True,
        )

    async def _fanout_task(self) -> None:
        while not self._stop.is_set():
            try:
                ev = await asyncio.wait_for(self._event_q.get(), timeout=0.25)
            except asyncio.TimeoutError:
                continue
            for cb in list(self._subscribers):
                try:
                    res = cb(ev)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception:
                    # Subscribers must not be able to wedge the pipeline.
                    pass

    async def run(self) -> None:
        tasks = [
            asyncio.create_task(self._ingest_task(), name="ingest"),
            asyncio.create_task(self._fanout_task(), name="fanout"),
            *[
                asyncio.create_task(
                    self._decode_worker(), name=f"decode-{i}",
                )
                for i in range(self.decoder_workers)
            ],
        ]
        try:
            await self._stop.wait()
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
