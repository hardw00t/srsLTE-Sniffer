"""SQLite store for captured paging records and cell observations.

Replaces the original CSV-only output. Schema is intentionally narrow — the
journal (`journal.py`) is the source of truth for raw bytes; this DB is the
queryable view.
"""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path

from .decoder import SIB1, PagingRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS pagings (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,                -- unix epoch microseconds
    radio_type TEXT NOT NULL DEFAULT '4g',
    kind TEXT NOT NULL,                 -- 'imsi' | 's-tmsi' | 'tmsi' | ...
    cn_domain TEXT,                     -- 'ps' | 'cs'
    imsi TEXT,                          -- 15-digit string OR sha256 hash
    mcc TEXT,
    mnc TEXT,
    msin TEXT,
    mmec INTEGER,
    m_tmsi INTEGER,
    tmsi INTEGER,                       -- 2G/3G TMSI
    p_tmsi INTEGER,                     -- 3G P-TMSI
    ng_5g_s_tmsi INTEGER,               -- 5G NR ng-5G-S-TMSI (48-bit)
    i_rnti INTEGER,                     -- 5G NR INACTIVE I-RNTI
    full_i_rnti INTEGER,                -- 5G NR full I-RNTI
    earfcn INTEGER,
    arfcn INTEGER,                      -- 2G channel number
    cell_id INTEGER,
    raw_hex TEXT
);
CREATE INDEX IF NOT EXISTS idx_pagings_ts ON pagings(ts);
CREATE INDEX IF NOT EXISTS idx_pagings_imsi ON pagings(imsi);
CREATE INDEX IF NOT EXISTS idx_pagings_radio ON pagings(radio_type);
CREATE INDEX IF NOT EXISTS idx_pagings_mtmsi ON pagings(mmec, m_tmsi);
CREATE INDEX IF NOT EXISTS idx_pagings_tmsi ON pagings(tmsi);

CREATE TABLE IF NOT EXISTS cells (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    radio_type TEXT NOT NULL DEFAULT '4g',
    earfcn INTEGER,
    arfcn INTEGER,
    cell_id INTEGER,
    plmn TEXT,
    tac INTEGER,
    lac INTEGER,                        -- 2G/3G location area code
    si_periodicity INTEGER,
    raw_hex TEXT,
    UNIQUE(radio_type, earfcn, cell_id, plmn)
);
CREATE INDEX IF NOT EXISTS idx_cells_earfcn ON cells(earfcn);
CREATE INDEX IF NOT EXISTS idx_cells_radio ON cells(radio_type);

CREATE TABLE IF NOT EXISTS sibs (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    radio_type TEXT NOT NULL DEFAULT '4g',
    earfcn INTEGER,
    cell_id INTEGER,
    sib_type TEXT NOT NULL,
    raw_hex TEXT
);
CREATE INDEX IF NOT EXISTS idx_sibs_type ON sibs(sib_type);
"""

# Migration: ALTER existing v2.x captures.db files to v3 shape. Idempotent.
_MIGRATIONS = [
    "ALTER TABLE pagings ADD COLUMN radio_type TEXT NOT NULL DEFAULT '4g'",
    "ALTER TABLE pagings ADD COLUMN tmsi INTEGER",
    "ALTER TABLE pagings ADD COLUMN p_tmsi INTEGER",
    "ALTER TABLE pagings ADD COLUMN ng_5g_s_tmsi INTEGER",
    "ALTER TABLE pagings ADD COLUMN i_rnti INTEGER",
    "ALTER TABLE pagings ADD COLUMN full_i_rnti INTEGER",
    "ALTER TABLE pagings ADD COLUMN arfcn INTEGER",
    "ALTER TABLE cells ADD COLUMN radio_type TEXT NOT NULL DEFAULT '4g'",
    "ALTER TABLE cells ADD COLUMN arfcn INTEGER",
    "ALTER TABLE cells ADD COLUMN lac INTEGER",
    "ALTER TABLE sibs ADD COLUMN radio_type TEXT NOT NULL DEFAULT '4g'",
]


def _apply_migrations(conn) -> None:
    for sql in _MIGRATIONS:
        try:
            conn.execute(sql)
        except Exception:
            # ALTER ... ADD COLUMN fails when the column already exists.
            # SQLite has no "IF NOT EXISTS" for ADD COLUMN, so we eat the
            # exception. Idempotent in practice.
            pass


class CaptureDB:
    def __init__(self, path: str | Path = "captures.db") -> None:
        self.path = Path(path)
        # isolation_level=None puts the connection in autocommit mode — every
        # statement commits unless the caller wraps it in a `transaction()`
        # context. Tests + dashboard expect inserts to be visible immediately.
        self._conn = sqlite3.connect(self.path, isolation_level=None)
        # Order matters: migrate first so the v2-shaped tables grow the new
        # columns BEFORE we run the v3 schema (which creates indexes on those
        # new columns). For fresh databases the migrations are no-ops.
        _apply_migrations(self._conn)
        self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self):
        self._conn.execute("BEGIN")
        try:
            yield self._conn
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self._conn.close()

    # ----- inserts -----

    def insert_paging(
        self,
        record: PagingRecord,
        *,
        ts_us: int | None = None,
        earfcn: int | None = None,
        cell_id: int | None = None,
        raw_hex: str | None = None,
        radio_type: str = "4g",
        arfcn: int | None = None,
    ) -> int:
        ts = ts_us if ts_us is not None else int(time.time() * 1e6)
        mcc = mnc = msin = None
        if record.kind == "imsi" and record.imsi and len(record.imsi) >= 5:
            mcc = record.imsi[:3]
            # MNC may be 2 or 3 digits — we conservatively assume 2 here.
            # Track 4 / scanner can correct using known-MCC tables.
            mnc = record.imsi[3:5]
            msin = record.imsi[5:]
        cur = self._conn.execute(
            """INSERT INTO pagings
                (ts, radio_type, kind, cn_domain, imsi, mcc, mnc, msin,
                 mmec, m_tmsi, earfcn, arfcn, cell_id, raw_hex)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ts, radio_type, record.kind, record.cn_domain, record.imsi,
                mcc, mnc, msin, record.mmec, record.m_tmsi,
                earfcn, arfcn, cell_id, raw_hex,
            ),
        )
        return cur.lastrowid or 0

    def insert_wide_paging(
        self,
        wide,  # WidePagingRecord (avoid hard import for back-compat)
        *,
        ts_us: int | None = None,
        cell_id: int | None = None,
        earfcn: int | None = None,
        arfcn: int | None = None,
        raw_hex: str | None = None,
    ) -> int:
        """Insert a multi-radio WidePagingRecord — used by the 2G/3G/5G
        decoders. Falls back to insert_paging shape for 4G."""
        ts = ts_us if ts_us is not None else int(time.time() * 1e6)
        cur = self._conn.execute(
            """INSERT INTO pagings
                (ts, radio_type, kind, imsi, mmec, m_tmsi, tmsi, p_tmsi,
                 ng_5g_s_tmsi, i_rnti, full_i_rnti,
                 earfcn, arfcn, cell_id, raw_hex)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ts, wide.radio_type, wide.kind, wide.imsi,
                wide.mmec, wide.m_tmsi, wide.tmsi, wide.p_tmsi,
                wide.ng_5g_s_tmsi, wide.i_rnti, wide.full_i_rnti,
                earfcn, arfcn, cell_id, raw_hex,
            ),
        )
        return cur.lastrowid or 0

    def insert_pagings(
        self,
        records: Iterable[PagingRecord],
        **kwargs,
    ) -> int:
        n = 0
        for r in records:
            self.insert_paging(r, **kwargs)
            n += 1
        return n

    def insert_cell(
        self,
        sib1: SIB1,
        *,
        earfcn: int | None = None,
        cell_id: int | None = None,
        raw_hex: str | None = None,
        ts_us: int | None = None,
    ) -> int:
        ts = ts_us if ts_us is not None else int(time.time() * 1e6)
        cid = cell_id if cell_id is not None else sib1.cell_id
        plmn = str(sib1.plmns[0]) if sib1.plmns else None
        cur = self._conn.execute(
            """INSERT OR IGNORE INTO cells
                (ts, earfcn, cell_id, plmn, tac, si_periodicity, raw_hex)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ts, earfcn, cid, plmn, sib1.tracking_area_code,
             sib1.si_periodicity, raw_hex),
        )
        return cur.lastrowid or 0

    def insert_sib(
        self,
        sib_type: str,
        *,
        earfcn: int | None = None,
        cell_id: int | None = None,
        raw_hex: str | None = None,
        ts_us: int | None = None,
    ) -> int:
        ts = ts_us if ts_us is not None else int(time.time() * 1e6)
        cur = self._conn.execute(
            """INSERT INTO sibs (ts, earfcn, cell_id, sib_type, raw_hex)
               VALUES (?, ?, ?, ?, ?)""",
            (ts, earfcn, cell_id, sib_type, raw_hex),
        )
        return cur.lastrowid or 0

    # ----- queries -----

    def count(self, table: str = "pagings") -> int:
        if table not in {"pagings", "cells", "sibs"}:
            raise ValueError(f"unknown table: {table}")
        cur = self._conn.execute(f"SELECT COUNT(*) FROM {table}")
        return int(cur.fetchone()[0])

    def recent_pagings(self, limit: int = 50) -> list[dict]:
        cur = self._conn.execute(
            "SELECT ts, kind, imsi, mmec, m_tmsi, earfcn, cell_id "
            "FROM pagings ORDER BY ts DESC LIMIT ?",
            (limit,),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def imsis_by_count(self, limit: int = 20) -> list[dict]:
        cur = self._conn.execute(
            "SELECT imsi, COUNT(*) AS n, MIN(ts) AS first_seen, MAX(ts) AS last_seen "
            "FROM pagings WHERE kind='imsi' AND imsi IS NOT NULL "
            "GROUP BY imsi ORDER BY n DESC LIMIT ?",
            (limit,),
        )
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def stats(self) -> dict:
        s = {
            "pagings": self.count("pagings"),
            "cells": self.count("cells"),
            "sibs": self.count("sibs"),
        }
        cur = self._conn.execute(
            "SELECT kind, COUNT(*) FROM pagings GROUP BY kind"
        )
        for kind, n in cur.fetchall():
            s[f"pagings_{kind}"] = n
        return s

    def purge(self) -> None:
        """Delete all rows. Intended for incident-response."""
        self._conn.executescript(
            "DELETE FROM pagings; DELETE FROM cells; DELETE FROM sibs;"
        )

    def prune_older_than(self, ts_us_cutoff: int) -> dict[str, int]:
        """Delete records with ts < cutoff. Returns counts per table."""
        out = {}
        for table in ("pagings", "cells", "sibs"):
            cur = self._conn.execute(
                f"DELETE FROM {table} WHERE ts < ?",
                (ts_us_cutoff,),
            )
            out[table] = cur.rowcount
        # SQLite needs an explicit VACUUM to reclaim space.
        self._conn.execute("VACUUM")
        return out
