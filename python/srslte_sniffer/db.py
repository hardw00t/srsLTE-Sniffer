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
    kind TEXT NOT NULL,                 -- 'imsi' | 's-tmsi' | 'unknown'
    cn_domain TEXT,                     -- 'ps' | 'cs'
    imsi TEXT,                          -- 15-digit string OR sha256 hash
    mcc TEXT,
    mnc TEXT,
    msin TEXT,
    mmec INTEGER,
    m_tmsi INTEGER,
    earfcn INTEGER,
    cell_id INTEGER,
    raw_hex TEXT
);
CREATE INDEX IF NOT EXISTS idx_pagings_ts ON pagings(ts);
CREATE INDEX IF NOT EXISTS idx_pagings_imsi ON pagings(imsi);
CREATE INDEX IF NOT EXISTS idx_pagings_mtmsi ON pagings(mmec, m_tmsi);

CREATE TABLE IF NOT EXISTS cells (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    earfcn INTEGER,
    cell_id INTEGER,
    plmn TEXT,
    tac INTEGER,
    si_periodicity INTEGER,
    raw_hex TEXT,
    UNIQUE(earfcn, cell_id, plmn)
);
CREATE INDEX IF NOT EXISTS idx_cells_earfcn ON cells(earfcn);

CREATE TABLE IF NOT EXISTS sibs (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL,
    earfcn INTEGER,
    cell_id INTEGER,
    sib_type TEXT NOT NULL,
    raw_hex TEXT
);
CREATE INDEX IF NOT EXISTS idx_sibs_type ON sibs(sib_type);
"""


class CaptureDB:
    def __init__(self, path: str | Path = "captures.db") -> None:
        self.path = Path(path)
        # isolation_level=None puts the connection in autocommit mode — every
        # statement commits unless the caller wraps it in a `transaction()`
        # context. Tests + dashboard expect inserts to be visible immediately.
        self._conn = sqlite3.connect(self.path, isolation_level=None)
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
                (ts, kind, cn_domain, imsi, mcc, mnc, msin, mmec, m_tmsi,
                 earfcn, cell_id, raw_hex)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ts, record.kind, record.cn_domain, record.imsi,
                mcc, mnc, msin, record.mmec, record.m_tmsi,
                earfcn, cell_id, raw_hex,
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
