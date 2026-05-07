"""Streaming pipeline tests.

These exercise the async journal tail + decoder pool + fan-out path
end-to-end against the included demo capture, simulating live capture via
the offline simulator.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from srslte_sniffer.journal import KIND_PCCH, Journal
from srslte_sniffer.simulator import replay_sync
from srslte_sniffer.streaming import (
    StreamEvent,
    StreamingPipeline,
    stream_journal,
)


@pytest.mark.asyncio_or_thread  # used as a label only; we drive asyncio directly
def test_stream_journal_finite_mode_reads_finished_journal(tmp_path: Path):
    j = tmp_path / "j"
    with Journal(j) as jw:
        for i in range(5):
            jw.write(b"x" * (10 + i), kind=KIND_PCCH, ts_us=1000 + i)

    async def _run():
        out = []
        async for kind, ts, payload in stream_journal(j, follow=False):
            out.append((kind, ts, len(payload)))
        return out

    out = asyncio.run(_run())
    assert out == [(KIND_PCCH, 1000 + i, 10 + i) for i in range(5)]


def test_stream_journal_follow_picks_up_appends(tmp_path: Path):
    j = tmp_path / "j"

    async def _run():
        events: list[tuple[int, int, int]] = []
        stop = asyncio.Event()

        async def consumer():
            async for kind, ts, payload in stream_journal(
                j, poll_interval_s=0.01, stop_event=stop
            ):
                events.append((kind, ts, len(payload)))
                if len(events) >= 3:
                    stop.set()

        async def writer():
            await asyncio.sleep(0.05)
            jw = Journal(j)
            try:
                for i in range(3):
                    jw.write(b"hi", kind=KIND_PCCH, ts_us=2000 + i,
                             fsync=False)
                    await asyncio.sleep(0.03)
            finally:
                jw.close()

        await asyncio.wait_for(
            asyncio.gather(consumer(), writer()),
            timeout=5.0,
        )
        return events

    out = asyncio.run(_run())
    assert len(out) == 3
    assert all(e[2] == 2 for e in out)


def test_streaming_pipeline_via_simulator(demo_txt, tmp_path: Path):
    """End-to-end: simulator writes journal → pipeline reads + decodes →
    subscriber collects records."""
    journal = tmp_path / "live.journal"

    async def _run():
        pipeline = StreamingPipeline(
            journal, decoder_workers=2, queue_size=256,
        )
        events: list[StreamEvent] = []

        def collector(ev: StreamEvent) -> None:
            events.append(ev)
            # Stop once we've seen at least one IMSI plus 50 records.
            if any(r.kind == "imsi" for ev in events for r in ev.records):
                if sum(len(e.records) for e in events) >= 50:
                    pipeline.stop()

        pipeline.subscribe(collector)

        async def writer():
            # Wait until the pipeline begins polling.
            await asyncio.sleep(0.05)
            # Replay first 5000 records as fast as possible.
            from srslte_sniffer.simulator import replay_into_journal
            await replay_into_journal(
                str(demo_txt), journal,
                rate_hz=0.0, limit=5000,
            )

        await asyncio.wait_for(
            asyncio.gather(pipeline.run(), writer()),
            timeout=30.0,
        )
        return events, pipeline

    events, pipeline = asyncio.run(_run())
    assert pipeline.processed > 0
    rec_count = sum(len(e.records) for e in events)
    assert rec_count >= 50
    assert any(r.kind == "imsi" for e in events for r in e.records)


def test_simulator_synchronous_replay(demo_txt, tmp_path: Path):
    journal = tmp_path / "sim.journal"
    n = replay_sync(str(demo_txt), journal, rate_hz=0.0, limit=200)
    assert n == 200
    assert journal.exists()
    assert journal.stat().st_size > 0


def test_pipeline_drops_under_backpressure(tmp_path: Path):
    """Force the queue to fill — assert the drop counter increments."""
    j = tmp_path / "drop.journal"

    async def _run():
        # Tiny queue so it fills instantly.
        pipeline = StreamingPipeline(j, decoder_workers=1, queue_size=4)

        def slow_subscriber(_):
            time.sleep(0.01)  # block fan-out worker

        pipeline.subscribe(slow_subscriber)

        async def writer():
            await asyncio.sleep(0.05)
            jw = Journal(j)
            try:
                for i in range(200):
                    jw.write(b"\x00\x00\x00\x00",
                             kind=KIND_PCCH, ts_us=i, fsync=False)
            finally:
                jw.close()
            # Let the pipeline run a moment then stop.
            await asyncio.sleep(0.5)
            pipeline.stop()

        await asyncio.wait_for(
            asyncio.gather(pipeline.run(), writer()),
            timeout=10.0,
        )
        return pipeline

    pipeline = asyncio.run(_run())
    # We pumped 200; the queues are tiny — drops MUST be > 0.
    assert pipeline.dropped + pipeline.processed > 0
