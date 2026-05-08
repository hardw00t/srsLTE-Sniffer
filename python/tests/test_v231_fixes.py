"""Regression tests for the v2.3.1 plumbing fixes.

Each test pins a real bug discovered in the v2.3 audit (hub multi-radio
loss, analyzer GSM dispatch, anomaly radio_type filter, NR dry-run PDUs).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from srslte_sniffer.analyzer import analyze_frames
from srslte_sniffer.dashboard import make_app
from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.decoder_2g import MT_PAGING_TYPE_2
from srslte_sniffer.hub import PushClient, PushConfig, make_hub_app
from srslte_sniffer.pcap_io import CapturedFrame
from srslte_sniffer.streaming import StreamEvent

_REPO = Path(__file__).resolve().parents[2]


# -- Fix 2: hub propagates radio_type + wide identifiers -----------------


def test_hub_ingest_preserves_radio_type_and_tmsi(tmp_path: Path):
    db_path = tmp_path / "hub.db"
    app = make_hub_app(str(db_path))
    client = TestClient(app)

    body = json.dumps({
        "node_id": "sn1", "ts_us": 1, "kind": "paging",
        "radio_type": "2g", "arfcn": 947,
        "record": {"kind": "tmsi", "tmsi": 0xCAFEBABE},
    })
    r = client.post("/ingest", content=body,
                    headers={"content-type": "application/x-ndjson"})
    assert r.status_code == 200
    assert r.json() == {"inserted": 1, "skipped": 0}

    db = CaptureDB(db_path)
    try:
        rows = db._conn.execute(
            "SELECT radio_type, kind, tmsi, arfcn FROM pagings"
        ).fetchall()
        assert rows == [("2g", "tmsi", 0xCAFEBABE, 947)]
    finally:
        db.close()


def test_hub_ingest_preserves_5g_ng_stmsi(tmp_path: Path):
    db_path = tmp_path / "hub.db"
    client = TestClient(make_hub_app(str(db_path)))
    body = json.dumps({
        "node_id": "sn1", "ts_us": 1, "kind": "paging",
        "radio_type": "5g-sa",
        "record": {"kind": "ng-5g-s-tmsi",
                   "ng_5g_s_tmsi": 0x123456789ABC},
    })
    r = client.post("/ingest", content=body)
    assert r.status_code == 200

    db = CaptureDB(db_path)
    try:
        row = db._conn.execute(
            "SELECT radio_type, kind, ng_5g_s_tmsi FROM pagings"
        ).fetchone()
        assert row == ("5g-sa", "ng-5g-s-tmsi", 0x123456789ABC)
    finally:
        db.close()


def test_hub_ingest_v2_2_clients_default_to_4g(tmp_path: Path):
    """Backward-compat: a v2.2 client emitting only the legacy fields
    (no radio_type) still lands as 4g."""
    db_path = tmp_path / "hub.db"
    client = TestClient(make_hub_app(str(db_path)))
    body = json.dumps({
        "node_id": "sn1", "ts_us": 1, "kind": "paging",
        "record": {"kind": "s-tmsi", "mmec": 22, "m_tmsi": 0xDEADBEEF},
    })
    r = client.post("/ingest", content=body)
    assert r.status_code == 200

    db = CaptureDB(db_path)
    try:
        row = db._conn.execute(
            "SELECT radio_type, kind, mmec, m_tmsi FROM pagings"
        ).fetchone()
        assert row == ("4g", "s-tmsi", 22, 0xDEADBEEF)
    finally:
        db.close()


def test_pushclient_serialize_wide_helper():
    from srslte_sniffer.decoder_common import WidePagingRecord

    w = WidePagingRecord(
        radio_type="3g", kind="p-tmsi", p_tmsi=0xCAFEBABE,
    )
    payload = PushClient.serialize_wide(
        w, node_id="sn1", ts_us=1234, cell_id=42, arfcn=10560,
    )
    assert payload["radio_type"] == "3g"
    assert payload["arfcn"] == 10560
    assert payload["cell_id"] == 42
    assert payload["record"]["p_tmsi"] == 0xCAFEBABE


def test_pushclient_legacy_serialize_emits_radio_type():
    """The legacy PagingRecord-shaped path must now include radio_type
    in the wire format so the hub stores it correctly."""
    cfg = PushConfig(url="x", node_id="n")
    pc = PushClient(cfg)
    ev = StreamEvent(
        kind=1, ts_us=1, raw=b"",
        records=[PagingRecord(kind="s-tmsi", cn_domain="ps",
                              mmec=22, m_tmsi=1)],
        decode_ok=True,
    )
    out = pc._serialize(ev)
    assert out[0]["radio_type"] == "4g"


# -- Fix 3: analyzer dispatches GSM L3 vs LTE PCCH ----------------------


def test_analyzer_routes_gsm_l3_to_2g_decoder(tmp_path: Path):
    """Build a journal with one GSM L3 paging frame, run analyze, assert
    the 2G TMSIs land in the DB (not lost as LTE-PCCH parse failures)."""
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        gsm_payload = (
            bytes([0x06, MT_PAGING_TYPE_2, 0x00])  # PD/MT/page-mode
            + (0xCAFEBABE).to_bytes(4, "big")
            + (0xDEADBEEF).to_bytes(4, "big")
        )
        frames = [CapturedFrame(
            payload=gsm_payload, raw=gsm_payload,
            framing="pcch", timestamp_us=1,
        )]
        stats = analyze_frames(iter(frames), db=db, hash_identifiers=False)
        # Both TMSIs should have landed as 2g rows.
        assert stats.pagings_2g == 2
        rows = db._conn.execute(
            "SELECT radio_type, kind, tmsi FROM pagings ORDER BY tmsi"
        ).fetchall()
        assert rows == [
            ("2g", "tmsi", 0xCAFEBABE),
            ("2g", "tmsi", 0xDEADBEEF),
        ]
    finally:
        db.close()


def test_analyzer_lte_path_unchanged_by_dispatch(tmp_path: Path):
    """Sanity: a real LTE PCCH frame still goes down the LTE branch."""
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        lte_payload = bytes.fromhex("40016c445a8200dabf6960450000")
        frames = [CapturedFrame(
            payload=lte_payload, raw=lte_payload,
            framing="pcch", timestamp_us=1,
        )]
        stats = analyze_frames(iter(frames), db=db, hash_identifiers=False)
        assert stats.decoded_pcch == 1
        assert stats.pagings_2g == 0
        row = db._conn.execute(
            "SELECT radio_type, kind FROM pagings"
        ).fetchone()
        assert row == ("4g", "s-tmsi")
    finally:
        db.close()


# -- Fix 4: /api/anomalies radio_type filter ----------------------------


def _seed_mixed_radios(db_path: Path) -> None:
    db = CaptureDB(db_path)
    try:
        # 4G cell with rogue PLMN, 2G cell with allowed PLMN.
        db._conn.execute(
            "INSERT INTO cells (ts, radio_type, cell_id, plmn, tac, "
            "si_periodicity) VALUES (1, '4g', 1, '999-99', 1, 8)"
        )
        db._conn.execute(
            "INSERT INTO cells (ts, radio_type, cell_id, plmn, tac, "
            "si_periodicity) VALUES (1, '2g', 2, '525-05', 2, 8)"
        )
    finally:
        db.close()


def test_anomalies_default_filters_to_4g(tmp_path: Path):
    db_path = tmp_path / "x.db"
    _seed_mixed_radios(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/anomalies?allowed_plmns=525-05")
    assert r.status_code == 200
    rules = {a["rule"] for a in r.json()}
    # 4G rogue cell should fire unknown_plmn; 2G cell ignored.
    assert "unknown_plmn" in rules


def test_anomalies_radio_type_2g(tmp_path: Path):
    db_path = tmp_path / "x.db"
    _seed_mixed_radios(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/anomalies?radio_type=2g&allowed_plmns=525-05")
    assert r.status_code == 200
    # 2G cell on allowed PLMN — no unknown_plmn.
    rules = {a["rule"] for a in r.json()}
    assert "unknown_plmn" not in rules


def test_anomalies_radio_type_all(tmp_path: Path):
    db_path = tmp_path / "x.db"
    _seed_mixed_radios(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/anomalies?radio_type=all&allowed_plmns=525-05")
    assert r.status_code == 200


# -- Fix 1: NR dry-run PDUs decode to non-empty record list -------------


def test_nr_sniffer_dry_run_produces_real_records():
    """Run nr_sniffer --dry-run, then push the journal back through the
    NR decoder and assert at least one real paging record comes out
    (not zero like the v2.3 vacuous PDUs)."""
    bin_path = _REPO / "build/src/nr_sniffer/nr_sniffer"
    if not bin_path.exists():
        # CI may not have built; skip rather than fail.
        import pytest
        pytest.skip("nr_sniffer binary not built")

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        journal = tdp / "nr.journal"
        pcap = tdp / "nr.pcapng"
        subprocess.run(
            [str(bin_path), "--dry-run", "--dry-run-count", "9",
             "-j", str(journal), "-p", str(pcap)],
            check=True, capture_output=True,
        )
        from srslte_sniffer.journal import KIND_PCCH, replay
        from srslte_sniffer.nr_decoder import (
            decode_nr_pcch,
            extract_nr_paging_records,
        )

        total_records = 0
        seen_kinds: set[str] = set()
        for kind, _ts, payload in replay(journal):
            if kind != KIND_PCCH:
                continue
            res = decode_nr_pcch(payload)
            assert res.ok, res.error
            for r in extract_nr_paging_records(res):
                total_records += 1
                seen_kinds.add(r.kind)
        # 9 PDUs in the dry-run rotation (3 variants × 3): at minimum
        # 9 records (one variant has 2 records → 12 total).
        assert total_records >= 9, total_records
        # Both ng-5g-s-tmsi and fulli-rnti variants must appear.
        assert "ng-5g-s-tmsi" in seen_kinds
        assert "fulli-rnti" in seen_kinds
