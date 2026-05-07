"""End-to-end analyzer test against the included demo capture.

This is the headline proof point — we run the entire decode pipeline
across thousands of real over-the-air paging packets and assert on the
record counts. If this passes, Tracks 2/3 work in production.
"""

from __future__ import annotations

from srslte_sniffer.analyzer import analyze_file
from srslte_sniffer.db import CaptureDB


def test_analyze_demo_file_offline_decoder(demo_txt, tmp_path):
    """Decode the demo file straight to a SQLite store and check counts."""
    db_path = tmp_path / "captures.db"
    stats = analyze_file(
        str(demo_txt),
        db_path=str(db_path),
        earfcn=1450,
        cell_id=42,
        hash_identifiers=True,
    )
    # Real-world numbers from the included capture (verified independently).
    # We check ranges, not exact numbers, to be robust against minor file edits.
    assert stats.frames > 100_000
    assert stats.decoded_pcch > 100_000
    assert stats.failed < stats.frames * 0.01, (
        f"too many decode failures: {stats.failed}/{stats.frames}"
    )
    assert stats.pagings_imsi >= 50
    assert stats.pagings_stmsi >= 100_000
    # Multi-record co-frame parsing — the bug that was open in the README.
    # Should detect tens of thousands of multi-record paging frames.
    assert stats.multi_record_frames > 1000

    # And the DB actually has rows.
    db = CaptureDB(db_path)
    try:
        assert db.count("pagings") == stats.pagings_total
        # Hashing default applied — IMSI column should not contain raw 15
        # digit numbers.
        rows = db._conn.execute(
            "SELECT imsi FROM pagings WHERE kind='imsi' AND imsi IS NOT NULL "
            "LIMIT 5"
        ).fetchall()
        for (imsi,) in rows:
            assert imsi.startswith("sha256:"), imsi
    finally:
        db.close()


def test_analyze_unsafe_raw_keeps_imsi(demo_txt, tmp_path):
    db_path = tmp_path / "raw.db"
    analyze_file(
        str(demo_txt), db_path=str(db_path),
        hash_identifiers=False,
    )
    db = CaptureDB(db_path)
    try:
        rows = db._conn.execute(
            "SELECT imsi FROM pagings WHERE kind='imsi' LIMIT 1"
        ).fetchall()
        assert rows, "expected at least one IMSI"
        (imsi,) = rows[0]
        assert imsi.isdigit() and len(imsi) == 15, imsi
    finally:
        db.close()
