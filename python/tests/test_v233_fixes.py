"""v2.3.3 regression tests — six audit follow-ups (A–F)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from srslte_sniffer.analyzer import analyze_frames
from srslte_sniffer.cli import main
from srslte_sniffer.dashboard import make_app
from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder_2g import MT_PAGING_TYPE_2
from srslte_sniffer.decoder_common import WidePagingRecord
from srslte_sniffer.hub import PushClient, PushConfig, make_hub_app
from srslte_sniffer.pcap_io import CapturedFrame
from srslte_sniffer.rogue_detector import (
    GsmCellSnapshot,
    NRCellSnapshot,
    UmtsCellSnapshot,
    run_all,
)
from srslte_sniffer.synthesize import (
    all_patterns,
    materialize,
    pattern_2g_imsi_storm,
    pattern_3g_p_tmsi_movement,
    pattern_5g_ng_stmsi_churn,
)


# -- Fix A: cn_domain plumbed through wide path -------------------------


def test_wide_paging_record_has_cn_domain():
    w = WidePagingRecord(radio_type="2g", kind="tmsi",
                         tmsi=0xCAFEBABE, cn_domain="cs")
    assert w.cn_domain == "cs"


def test_db_insert_wide_paging_persists_cn_domain(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        w = WidePagingRecord(radio_type="3g", kind="p-tmsi",
                             p_tmsi=42, cn_domain="ps")
        db.insert_wide_paging(w, ts_us=1, cell_id=1)
        row = db._conn.execute(
            "SELECT cn_domain FROM pagings"
        ).fetchone()
        assert row == ("ps",)
    finally:
        db.close()


def test_hub_ingest_preserves_cn_domain(tmp_path: Path):
    db_path = tmp_path / "hub.db"
    client = TestClient(make_hub_app(str(db_path)))
    body = json.dumps({
        "node_id": "sn1", "ts_us": 1, "kind": "paging",
        "radio_type": "4g",
        "record": {"kind": "s-tmsi", "mmec": 22, "m_tmsi": 1,
                   "cn_domain": "cs"},
    })
    r = client.post("/ingest", content=body)
    assert r.status_code == 200

    db = CaptureDB(db_path)
    try:
        row = db._conn.execute(
            "SELECT cn_domain FROM pagings"
        ).fetchone()
        assert row == ("cs",)
    finally:
        db.close()


def test_pushclient_serialize_wide_includes_cn_domain():
    w = WidePagingRecord(radio_type="2g", kind="imsi",
                         imsi="525058131997813", cn_domain="cs")
    payload = PushClient.serialize_wide(
        w, node_id="sn1", ts_us=1, cell_id=42,
    )
    assert payload["record"]["cn_domain"] == "cs"


# -- Fix B: track --radio-type 2g routes to move ------------------------


def test_track_redirects_to_move_for_non_4g(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        # Two 2G TMSIs on different cells = a movement
        for cid in (1, 2):
            db.insert_wide_paging(
                WidePagingRecord(radio_type="2g", kind="tmsi",
                                 tmsi=0xCAFEBABE),
                ts_us=cid * 1_000_000, cell_id=cid,
            )
    finally:
        db.close()

    r = CliRunner().invoke(
        main, ["track", "--db", str(db_path), "--radio-type", "2g"]
    )
    assert r.exit_code == 0
    # The redirect notice and the JSON both end up in r.output (Click's
    # CliRunner captures stdout+stderr together by default).
    assert "routes to `move`" in r.output
    # Strip the leading stderr line(s) that start with '#' to get JSON.
    json_text = "\n".join(
        ln for ln in r.output.splitlines() if not ln.startswith("#")
    )
    out = json.loads(json_text)
    assert "2g-tmsi:3405691582" in out


def test_track_remains_4g_only_for_default(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        from srslte_sniffer.decoder import PagingRecord

        db.insert_paging(
            PagingRecord(kind="imsi", cn_domain="ps",
                         imsi="525050000000001"),
            ts_us=1, cell_id=1,
        )
    finally:
        db.close()
    r = CliRunner().invoke(main, ["track", "--db", str(db_path)])
    assert r.exit_code == 0
    # Default 4G path returns the build_tracks shape (list of dicts).
    out = json.loads(r.output)
    assert isinstance(out, list)


# -- Fix C: per-gen rules wired into run_all ---------------------------


def test_run_all_invokes_2g_rules_when_snapshots_provided():
    cells = []
    timeline = []
    gsm = [GsmCellSnapshot(cell_id=10, arfcn=947, cipher_mode="A5/0")]
    out = run_all(cells, timeline, gsm_cells=gsm)
    assert any(a.rule == "gsm_a5_0_announced" for a in out)


def test_run_all_invokes_3g_rules_when_snapshots_provided():
    out = run_all(
        [], [],
        umts_cells=[UmtsCellSnapshot(
            cell_id=20, plmn="525-05",
            advertises_rel99_only=True,
        )],
    )
    assert any(a.rule == "umts_rel99_only" for a in out)


def test_run_all_invokes_5g_rules_when_snapshots_provided():
    out = run_all(
        [], [],
        nr_cells=[NRCellSnapshot(
            cell_id=30, plmn="525-05",
            suci_replays_per_min=10.0,
        )],
    )
    assert any(a.rule == "nr_suci_replay" for a in out)


def test_run_all_skips_per_gen_rules_by_default():
    """No per-gen snapshots passed → no per-gen rules fire."""
    out = run_all([], [])
    rule_names = {a.rule for a in out}
    assert "gsm_a5_0_announced" not in rule_names
    assert "umts_rel99_only" not in rule_names
    assert "nr_suci_replay" not in rule_names


# -- Fix D: dashboard renders wide columns -----------------------------


def test_dashboard_index_renders_wide_columns(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        db.insert_wide_paging(
            WidePagingRecord(radio_type="5g-sa", kind="ng-5g-s-tmsi",
                             ng_5g_s_tmsi=0xABCDEF, cn_domain="ps"),
            ts_us=1, cell_id=42, arfcn=10560,
        )
    finally:
        db.close()
    client = TestClient(make_app(str(db_path)))
    r = client.get("/")
    assert r.status_code == 200
    # The radio_type and the 5G identifier name must appear in the HTML.
    assert "5g-sa" in r.text
    assert "ng-5G-S-TMSI" in r.text


# -- Fix E: analyzer 'unknown' framing tries GSM ----------------------


def test_analyzer_unknown_framing_routes_gsm(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        # Construct a valid 2G L3 RR Paging Type 2 with two TMSIs.
        gsm_payload = (
            bytes([0x06, MT_PAGING_TYPE_2, 0x00])
            + (0xCAFEBABE).to_bytes(4, "big")
            + (0xDEADBEEF).to_bytes(4, "big")
        )
        # Note framing="unknown" — tests the v2.3.3 fallback.
        frames = [CapturedFrame(
            payload=gsm_payload, raw=gsm_payload,
            framing="unknown", timestamp_us=1,
        )]
        stats = analyze_frames(iter(frames), db=db, hash_identifiers=False)
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


# -- Fix F: 2G/3G/5G synthetic patterns --------------------------------


def test_synthesize_includes_per_radio_patterns():
    names = {p.name for p in all_patterns()}
    assert "2g_imsi_storm" in names
    assert "2g_tmsi_churn" in names
    assert "3g_p_tmsi_movement" in names
    assert "5g_ng_stmsi_churn" in names


def test_materialize_2g_pattern_uses_wide_path(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_2g_imsi_storm(), db)
        rows = db._conn.execute(
            "SELECT DISTINCT radio_type, kind FROM pagings"
        ).fetchall()
        assert rows == [("2g", "imsi")]
        assert db.count("pagings") == 50
    finally:
        db.close()


def test_materialize_3g_movement_pattern(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_3g_p_tmsi_movement(), db)
        rows = db._conn.execute(
            "SELECT DISTINCT radio_type, kind, p_tmsi FROM pagings"
        ).fetchall()
        assert rows == [("3g", "p-tmsi", 0xABCDEF01)]
        # Both rows on different cells
        cells = {r[0] for r in db._conn.execute(
            "SELECT DISTINCT cell_id FROM pagings"
        ).fetchall()}
        assert cells == {300, 301}
    finally:
        db.close()


def test_materialize_5g_pattern(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        materialize(pattern_5g_ng_stmsi_churn(), db)
        n = db._conn.execute(
            "SELECT COUNT(DISTINCT ng_5g_s_tmsi) FROM pagings "
            "WHERE radio_type='5g-sa'"
        ).fetchone()[0]
        assert n == 60
    finally:
        db.close()


# Silence unused import warnings.
_ = pytest
