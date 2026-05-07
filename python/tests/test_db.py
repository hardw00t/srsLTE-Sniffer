"""SQLite store tests."""

from __future__ import annotations

from pathlib import Path

from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PLMN, PagingRecord, SIB1


def test_schema_init(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        assert db.count("pagings") == 0
        assert db.count("cells") == 0
        assert db.count("sibs") == 0
    finally:
        db.close()


def test_insert_paging_imsi(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        rec = PagingRecord(kind="imsi", cn_domain="ps", imsi="525058131997813")
        rid = db.insert_paging(rec, ts_us=10_000_000, earfcn=1450, cell_id=1)
        assert rid > 0
        # MCC + 2-digit MNC carved out automatically
        row = db._conn.execute(
            "SELECT mcc, mnc, msin FROM pagings WHERE id=?", (rid,)
        ).fetchone()
        assert row == ("525", "05", "8131997813")
    finally:
        db.close()


def test_insert_cell_dedup(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        sib1 = SIB1(plmns=[PLMN(mcc="525", mnc="05")],
                    tracking_area_code=2001, cell_id=42, si_periodicity=8)
        db.insert_cell(sib1, earfcn=1450, cell_id=42)
        db.insert_cell(sib1, earfcn=1450, cell_id=42)
        # UNIQUE(earfcn, cell_id, plmn) — only one row.
        assert db.count("cells") == 1
    finally:
        db.close()


def test_purge(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        db.insert_paging(PagingRecord(kind="s-tmsi", cn_domain="ps",
                                      mmec=22, m_tmsi=0xC445A820))
        assert db.count("pagings") == 1
        db.purge()
        assert db.count("pagings") == 0
    finally:
        db.close()


def test_imsis_by_count(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        for i in range(3):
            db.insert_paging(
                PagingRecord(kind="imsi", cn_domain="ps",
                             imsi="525058131997813"),
                ts_us=1_000_000 + i,
            )
        db.insert_paging(
            PagingRecord(kind="imsi", cn_domain="ps", imsi="525058131997999"),
            ts_us=2_000_000,
        )
        rows = db.imsis_by_count(limit=10)
        assert rows[0]["imsi"] == "525058131997813"
        assert rows[0]["n"] == 3
    finally:
        db.close()
