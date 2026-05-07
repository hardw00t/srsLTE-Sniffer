"""Rogue-eNB rule tests."""

from __future__ import annotations

from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.rogue_detector import (CellSnapshot,
                                           detect_excessive_stmsi_churn,
                                           detect_imsi_paging_rate,
                                           detect_plmn_mismatch_in_tac,
                                           detect_si_periodicity_outlier,
                                           detect_unknown_plmn, run_all)
from srslte_sniffer.tracker import TimedPaging


def test_unknown_plmn():
    cells = [CellSnapshot(cell_id=1, plmn="999-99", tac=1, si_periodicity=8)]
    out = detect_unknown_plmn(cells, allowed_plmns={"525-01", "525-02", "525-05"})
    assert len(out) == 1
    assert out[0].rule == "unknown_plmn"
    assert out[0].severity == "high"


def test_plmn_mismatch_in_tac():
    cells = [
        CellSnapshot(cell_id=1, plmn="525-05", tac=2001, si_periodicity=8),
        CellSnapshot(cell_id=2, plmn="525-05", tac=2001, si_periodicity=8),
        CellSnapshot(cell_id=3, plmn="525-05", tac=2001, si_periodicity=8),
        CellSnapshot(cell_id=4, plmn="999-99", tac=2001, si_periodicity=8),
    ]
    out = detect_plmn_mismatch_in_tac(cells)
    assert len(out) == 1
    assert out[0].cell_id == 4
    assert out[0].plmn == "999-99"


def test_excessive_stmsi_churn():
    timeline = []
    for i in range(60):  # threshold default 50
        timeline.append(TimedPaging(
            record=PagingRecord(kind="s-tmsi", cn_domain="ps",
                                mmec=22, m_tmsi=i),
            ts_us=i, cell_id=99,
        ))
    out = detect_excessive_stmsi_churn(timeline, threshold=50)
    assert len(out) == 1
    assert out[0].cell_id == 99


def test_imsi_paging_rate():
    cells = [
        CellSnapshot(cell_id=1, plmn="525-05", tac=1, si_periodicity=8,
                     paging_imsi_count=30, paging_stmsi_count=70),
        CellSnapshot(cell_id=2, plmn="525-05", tac=1, si_periodicity=8,
                     paging_imsi_count=1, paging_stmsi_count=999),
    ]
    out = detect_imsi_paging_rate(cells)
    assert len(out) == 1
    assert out[0].cell_id == 1
    assert out[0].severity == "high"


def test_si_periodicity_outlier():
    cells = [
        CellSnapshot(cell_id=i, plmn="525-05", tac=1, si_periodicity=8)
        for i in range(1, 5)
    ]
    cells.append(
        CellSnapshot(cell_id=99, plmn="525-05", tac=1, si_periodicity=64)
    )
    out = detect_si_periodicity_outlier(cells)
    assert any(a.cell_id == 99 for a in out)


def test_run_all_aggregates():
    cells = [
        CellSnapshot(cell_id=1, plmn="525-05", tac=1, si_periodicity=8,
                     paging_imsi_count=0, paging_stmsi_count=100),
        CellSnapshot(cell_id=2, plmn="999-99", tac=1, si_periodicity=8,
                     paging_imsi_count=0, paging_stmsi_count=100),
    ]
    timeline = []
    out = run_all(cells, timeline, allowed_plmns={"525-05"})
    rules = {a.rule for a in out}
    assert "unknown_plmn" in rules
    assert "plmn_mismatch_in_tac" in rules
