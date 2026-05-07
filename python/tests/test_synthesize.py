"""Synthetic anomaly tests — assert each generated pattern triggers the
right rogue-eNB rule (and only that one, ignoring incidental noise)."""

from __future__ import annotations

from pathlib import Path

from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.rogue_detector import CellSnapshot, run_all
from srslte_sniffer.synthesize import (
    materialize,
    pattern_excessive_stmsi_churn,
    pattern_imsi_paging_storm,
    pattern_plmn_mismatch_in_tac,
    pattern_si_periodicity_outlier,
    pattern_unknown_plmn,
)
from srslte_sniffer.tracker import TimedPaging


def _run_detector(db: CaptureDB, *, allowed=None):
    cells = []
    for cid, plmn, tac, sip in db._conn.execute(
        "SELECT cell_id, plmn, tac, si_periodicity FROM cells"
    ).fetchall():
        ipage = db._conn.execute(
            "SELECT COUNT(*) FROM pagings WHERE cell_id=? AND kind='imsi'",
            (cid,),
        ).fetchone()[0]
        spage = db._conn.execute(
            "SELECT COUNT(*) FROM pagings WHERE cell_id=? AND kind='s-tmsi'",
            (cid,),
        ).fetchone()[0]
        cells.append(CellSnapshot(
            cell_id=cid, plmn=plmn, tac=tac, si_periodicity=sip,
            paging_imsi_count=ipage, paging_stmsi_count=spage,
        ))
    timeline = [
        TimedPaging(
            record=PagingRecord(kind=k, cn_domain=None,
                                imsi=imsi, mmec=mmec, m_tmsi=mtmsi),
            ts_us=ts, cell_id=cid,
        )
        for ts, k, imsi, mmec, mtmsi, cid in db._conn.execute(
            "SELECT ts, kind, imsi, mmec, m_tmsi, cell_id FROM pagings"
        ).fetchall()
    ]
    return run_all(cells, timeline, allowed_plmns=allowed)


def test_unknown_plmn_pattern_fires_rule(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_unknown_plmn(), db)
        anoms = _run_detector(db, allowed={"525-05"})
        assert any(a.rule == "unknown_plmn" for a in anoms)
    finally:
        db.close()


def test_plmn_mismatch_pattern_fires_rule(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_plmn_mismatch_in_tac(), db)
        anoms = _run_detector(db)
        rules = {a.rule for a in anoms}
        assert "plmn_mismatch_in_tac" in rules
    finally:
        db.close()


def test_churn_pattern_fires_rule(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_excessive_stmsi_churn(), db)
        anoms = _run_detector(db)
        assert any(a.rule == "excessive_stmsi_churn" for a in anoms)
    finally:
        db.close()


def test_imsi_storm_pattern_fires_rule(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_imsi_paging_storm(), db)
        anoms = _run_detector(db)
        rules = {a.rule for a in anoms}
        assert "excessive_imsi_paging" in rules
    finally:
        db.close()


def test_si_periodicity_outlier_fires_rule(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_si_periodicity_outlier(), db)
        anoms = _run_detector(db)
        assert any(a.rule == "si_periodicity_outlier" for a in anoms)
    finally:
        db.close()


def test_clean_baseline_no_anomalies(tmp_path: Path):
    """Sanity: no patterns + clean cells = no anomalies."""
    from srslte_sniffer.decoder import PLMN, SIB1

    db = CaptureDB(tmp_path / "x.db")
    try:
        for cid in range(1, 6):
            db.insert_cell(SIB1(
                plmns=[PLMN(mcc="525", mnc="05")],
                tracking_area_code=2001, cell_id=cid, si_periodicity=8,
            ), cell_id=cid)
            for j in range(20):
                db.insert_paging(PagingRecord(
                    kind="s-tmsi", cn_domain="ps",
                    mmec=22, m_tmsi=cid * 100 + j,
                ), cell_id=cid, ts_us=j * 1000)
        anoms = _run_detector(db, allowed={"525-05"})
        assert anoms == []
    finally:
        db.close()
