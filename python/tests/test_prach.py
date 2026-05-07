"""PRACH correlation tests — the analyzer logic; the realtime extractor
is out of scope (see docs/NR_REALTIME.md and Track E rationale)."""

from __future__ import annotations

from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.prach import (
    PrachEvent,
    attach_latency_histogram,
    correlate,
)
from srslte_sniffer.tracker import TimedPaging


def _p(ts: int, cell: int = 1) -> TimedPaging:
    return TimedPaging(
        record=PagingRecord(kind="s-tmsi", cn_domain="ps",
                            mmec=22, m_tmsi=ts),
        ts_us=ts, cell_id=cell,
    )


def test_pairs_within_window():
    pagings = [_p(1_000_000), _p(2_000_000)]
    prach = [
        PrachEvent(ts_us=1_010_000, cell_id=1, preamble_id=5),
        PrachEvent(ts_us=2_020_000, cell_id=1, preamble_id=7),
    ]
    out = correlate(pagings, prach, window_us=80_000)
    assert len(out) == 2
    assert out[0].delta_us == 10_000
    assert out[1].delta_us == 20_000


def test_skips_when_outside_window():
    pagings = [_p(1_000_000)]
    prach = [PrachEvent(ts_us=1_500_000, cell_id=1, preamble_id=1)]  # 500ms
    out = correlate(pagings, prach, window_us=80_000)
    assert out == []


def test_cell_filtering():
    pagings = [_p(1_000_000, cell=1)]
    prach = [PrachEvent(ts_us=1_010_000, cell_id=2, preamble_id=1)]
    out = correlate(pagings, prach, window_us=80_000)
    assert out == []


def test_no_double_assignment():
    pagings = [_p(1_000_000)]
    prach = [
        PrachEvent(ts_us=1_010_000, cell_id=1, preamble_id=1),
        PrachEvent(ts_us=1_020_000, cell_id=1, preamble_id=2),
    ]
    out = correlate(pagings, prach, window_us=80_000)
    # Only the first PRACH gets the paging — the second has no match left.
    assert len(out) == 1
    assert out[0].prach.preamble_id == 1


def test_latency_histogram():
    pagings = [_p(1_000_000), _p(2_000_000), _p(3_000_000)]
    prach = [
        PrachEvent(ts_us=p.ts_us + 5_000, cell_id=1, preamble_id=i)
        for i, p in enumerate(pagings)
    ]
    out = correlate(pagings, prach, window_us=80_000)
    hist = attach_latency_histogram(out, bin_ms=5)
    # All deltas are 5 ms → bin 5
    assert hist == {5: 3}
