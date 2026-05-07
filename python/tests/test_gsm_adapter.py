"""End-to-end test of the GSM adapter: synthesise a GSMTAP-wrapped
paging request, feed it through consume_one, verify it lands in the DB
tagged radio_type='2g'."""

from __future__ import annotations

from pathlib import Path

from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder_2g import MT_PAGING_TYPE_2
from srslte_sniffer.gsm_adapter import GSMAdapterStats, consume_bytes, consume_one
from srslte_sniffer.gsmtap import (
    GSMTAP_CHAN_PCH,
    GSMTAP_TYPE_UM,
    build_header,
)


def _gsmtap_pch_with_two_tmsis(t1: int, t2: int) -> bytes:
    payload = bytes([0x06, MT_PAGING_TYPE_2, 0x00]) + (
        t1.to_bytes(4, "big") + t2.to_bytes(4, "big")
    )
    return build_header(
        type_=GSMTAP_TYPE_UM, sub_type=GSMTAP_CHAN_PCH,
        arfcn=947, frame_number=1234,
    ) + payload


def test_consume_one_inserts_two_tmsis(tmp_path: Path):
    db_path = tmp_path / "g.db"
    db = CaptureDB(db_path)
    try:
        stats = GSMAdapterStats()
        consume_one(_gsmtap_pch_with_two_tmsis(0xCAFEBABE, 0xDEADBEEF),
                    db=db, stats=stats)
        assert stats.received == 1
        assert stats.pch_frames == 1
        assert stats.decoded == 1
        # Both TMSIs landed in the DB tagged 2g.
        rows = db._conn.execute(
            "SELECT radio_type, kind, tmsi, arfcn FROM pagings ORDER BY tmsi"
        ).fetchall()
        assert rows == [
            ("2g", "tmsi", 0xCAFEBABE, 947),
            ("2g", "tmsi", 0xDEADBEEF, 947),
        ]
    finally:
        db.close()


def test_consume_one_ignores_non_pch_frames(tmp_path: Path):
    db_path = tmp_path / "g.db"
    db = CaptureDB(db_path)
    try:
        stats = GSMAdapterStats()
        # AGCH header — not PCH
        hdr = build_header(type_=GSMTAP_TYPE_UM, sub_type=0x06, arfcn=947)
        consume_one(hdr + b"\x00\x00\x00", db=db, stats=stats)
        assert stats.received == 1
        assert stats.pch_frames == 0
        assert db.count("pagings") == 0
    finally:
        db.close()


def test_consume_bytes_helper(tmp_path: Path):
    pkts = [
        _gsmtap_pch_with_two_tmsis(0x01, 0x02),
        _gsmtap_pch_with_two_tmsis(0x03, 0x04),
    ]
    stats = consume_bytes(pkts, db_path=str(tmp_path / "g.db"))
    assert stats.received == 2
    assert stats.decoded == 2


def test_consume_one_drops_bad_gsmtap(tmp_path: Path):
    db = CaptureDB(tmp_path / "g.db")
    try:
        stats = GSMAdapterStats()
        consume_one(b"\xff\xff", db=db, stats=stats)
        assert stats.received == 1
        assert stats.pch_frames == 0
        assert stats.decoded == 0
        assert db.count("pagings") == 0
    finally:
        db.close()
