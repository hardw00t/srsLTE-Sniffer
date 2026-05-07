"""Retention prune tests."""

from __future__ import annotations

import time
from pathlib import Path

from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PagingRecord


def test_prune_older_than(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        now_us = int(time.time() * 1e6)
        # Three rows: 1 day, 7 days, and 60 days old
        for delta_days in (1, 7, 60):
            db.insert_paging(
                PagingRecord(kind="s-tmsi", cn_domain="ps",
                             mmec=22, m_tmsi=delta_days),
                ts_us=now_us - delta_days * 86_400 * 1_000_000,
            )
        assert db.count("pagings") == 3

        # Prune anything older than 14 days.
        cutoff = now_us - 14 * 86_400 * 1_000_000
        result = db.prune_older_than(cutoff)
        assert result["pagings"] == 1
        assert db.count("pagings") == 2
    finally:
        db.close()
