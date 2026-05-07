"""DB schema + WidePagingRecord storage tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder_common import WidePagingRecord


def test_radio_type_column_present(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        cols = [r[1] for r in db._conn.execute("PRAGMA table_info(pagings)")]
        assert "radio_type" in cols
        assert "tmsi" in cols
        assert "p_tmsi" in cols
        assert "ng_5g_s_tmsi" in cols
        assert "i_rnti" in cols
        assert "arfcn" in cols
    finally:
        db.close()


def test_insert_wide_paging_2g(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        w = WidePagingRecord(radio_type="2g", kind="tmsi", tmsi=0xCAFEBABE)
        db.insert_wide_paging(w, ts_us=1, arfcn=947)
        row = db._conn.execute(
            "SELECT radio_type, kind, tmsi, arfcn FROM pagings"
        ).fetchone()
        assert row == ("2g", "tmsi", 0xCAFEBABE, 947)
    finally:
        db.close()


def test_insert_wide_paging_5g(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        w = WidePagingRecord(
            radio_type="5g-sa", kind="ng-5g-s-tmsi",
            ng_5g_s_tmsi=0x123456789ABC,
        )
        db.insert_wide_paging(w, ts_us=1)
        row = db._conn.execute(
            "SELECT radio_type, kind, ng_5g_s_tmsi FROM pagings"
        ).fetchone()
        assert row == ("5g-sa", "ng-5g-s-tmsi", 0x123456789ABC)
    finally:
        db.close()


def test_v2_db_migrates_in_place(tmp_path: Path):
    """A v2 DB (no radio_type column) should be migrated cleanly when
    opened by the v3 CaptureDB."""
    p = tmp_path / "old.db"
    # Hand-build a v2-shaped DB and a row.
    raw = sqlite3.connect(p, isolation_level=None)
    raw.executescript("""
        CREATE TABLE pagings (
            id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL,
            cn_domain TEXT, imsi TEXT, mcc TEXT, mnc TEXT, msin TEXT,
            mmec INTEGER, m_tmsi INTEGER, earfcn INTEGER, cell_id INTEGER,
            raw_hex TEXT
        );
        CREATE TABLE cells (
            id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, earfcn INTEGER,
            cell_id INTEGER, plmn TEXT, tac INTEGER, si_periodicity INTEGER,
            raw_hex TEXT, UNIQUE(earfcn, cell_id, plmn)
        );
        CREATE TABLE sibs (
            id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, earfcn INTEGER,
            cell_id INTEGER, sib_type TEXT NOT NULL, raw_hex TEXT
        );
    """)
    raw.execute(
        "INSERT INTO pagings (ts, kind, imsi) VALUES (1, 'imsi', '525058')"
    )
    raw.close()

    # Open via the new CaptureDB — migrations must run.
    db = CaptureDB(p)
    try:
        cols = [r[1] for r in db._conn.execute("PRAGMA table_info(pagings)")]
        assert "radio_type" in cols
        # Existing row's radio_type defaults to '4g'.
        row = db._conn.execute(
            "SELECT radio_type, kind, imsi FROM pagings"
        ).fetchone()
        assert row == ("4g", "imsi", "525058")
    finally:
        db.close()
