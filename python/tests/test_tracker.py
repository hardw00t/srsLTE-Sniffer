"""TMSI tracker tests."""

from __future__ import annotations

from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.tracker import (TimedPaging, build_tracks, churn_per_cell,
                                    correlate)


def _imsi(imsi: str, ts: int, cell: int = 1) -> TimedPaging:
    return TimedPaging(
        record=PagingRecord(kind="imsi", cn_domain="ps", imsi=imsi),
        ts_us=ts, cell_id=cell,
    )


def _stmsi(mtmsi: int, ts: int, cell: int = 1) -> TimedPaging:
    return TimedPaging(
        record=PagingRecord(kind="s-tmsi", cn_domain="ps",
                            mmec=22, m_tmsi=mtmsi),
        ts_us=ts, cell_id=cell,
    )


def test_correlate_single_cooccurrence_high_confidence():
    timeline = [_imsi("525058131997813", ts=1_000_000),
                _stmsi(0xCAFEBABE, ts=1_010_000)]
    out = correlate(timeline, window_us=200_000)
    assert len(out) == 1
    assert out[0].imsi == "525058131997813"
    assert out[0].new_m_tmsi == 0xCAFEBABE
    assert out[0].confidence == 0.9


def test_correlate_high_churn_low_confidence():
    timeline = [_imsi("525058131997813", ts=1_000_000)]
    for i in range(20):
        timeline.append(_stmsi(i, ts=1_000_000 + i * 100))
    out = correlate(timeline, window_us=200_000)
    assert all(c.confidence < 0.5 for c in out)


def test_correlate_ignores_other_cells():
    timeline = [_imsi("525058131997813", ts=1_000_000, cell=1),
                _stmsi(0xCAFEBABE, ts=1_010_000, cell=2)]
    out = correlate(timeline, window_us=200_000)
    assert out == []


def test_build_tracks_groups_by_imsi():
    timeline = [_imsi("A", ts=1_000_000), _stmsi(1, ts=1_010_000),
                _imsi("A", ts=2_000_000), _stmsi(2, ts=2_010_000),
                _imsi("B", ts=3_000_000), _stmsi(3, ts=3_010_000)]
    tracks = build_tracks(timeline, window_us=200_000)
    by = {t.imsi: t for t in tracks}
    assert by["A"].pages == 2
    assert by["B"].pages == 1
    assert (22, 1) in by["A"].seen_stmsis
    assert (22, 2) in by["A"].seen_stmsis


def test_churn_per_cell():
    timeline = [_stmsi(1, ts=1, cell=1), _stmsi(2, ts=2, cell=1),
                _stmsi(1, ts=3, cell=1),  # repeat
                _stmsi(99, ts=4, cell=2)]
    c = churn_per_cell(timeline)
    assert c[1] == 2  # two distinct M-TMSI on cell 1
    assert c[2] == 1
