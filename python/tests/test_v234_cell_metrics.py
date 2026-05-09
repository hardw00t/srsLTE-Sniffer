"""v2.3.4 cell_metrics tests — schema, upsert, snapshot building, and
end-to-end detect with per-gen rules firing through the CLI/dashboard."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from fastapi.testclient import TestClient

from srslte_sniffer.cli import main
from srslte_sniffer.dashboard import make_app
from srslte_sniffer.db import CaptureDB


# -- Schema + upsert ----------------------------------------------------


def test_cell_metrics_table_present(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        cols = [r[1] for r in db._conn.execute(
            "PRAGMA table_info(cell_metrics)"
        )]
        assert "radio_type" in cols
        assert "cipher_mode" in cols
        assert "location_updates_per_min" in cols
        assert "rrc_reject_per_min" in cols
        assert "advertises_rel99_only" in cols
        assert "suci_replays_per_min" in cols
        assert "aka_failures_per_min" in cols
    finally:
        db.close()


def test_record_cell_metric_upsert_partial(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        # First write: cipher only.
        db.record_cell_metric(
            radio_type="2g", cell_id=10, plmn="525-05",
            cipher_mode="A5/0",
        )
        # Second write: location updates only — cipher must persist.
        db.record_cell_metric(
            radio_type="2g", cell_id=10, plmn="525-05",
            location_updates_per_min=42.0,
        )
        row = db._conn.execute(
            "SELECT cipher_mode, location_updates_per_min "
            "FROM cell_metrics WHERE cell_id=10"
        ).fetchone()
        assert row == ("A5/0", 42.0)
    finally:
        db.close()


def test_gsm_snapshots_round_trip(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        db.record_cell_metric(
            radio_type="2g", cell_id=10, plmn="525-05",
            arfcn=947, cipher_mode="A5/0",
            location_updates_per_min=50.0,
        )
        snaps = db.gsm_snapshots()
        assert len(snaps) == 1
        assert snaps[0].cell_id == 10
        assert snaps[0].arfcn == 947
        assert snaps[0].cipher_mode == "A5/0"
        assert snaps[0].location_updates_per_min == 50.0
    finally:
        db.close()


def test_umts_snapshots_rel99(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        db.record_cell_metric(
            radio_type="3g", cell_id=20, plmn="525-05",
            advertises_rel99_only=True,
            rrc_reject_per_min=80.0,
        )
        snaps = db.umts_snapshots()
        assert len(snaps) == 1
        assert snaps[0].advertises_rel99_only is True
        assert snaps[0].rrc_reject_per_min == 80.0
    finally:
        db.close()


def test_nr_snapshots_combines_sa_and_nsa(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        db.record_cell_metric(
            radio_type="5g-sa", cell_id=30, plmn="525-05",
            suci_replays_per_min=10.0,
        )
        db.record_cell_metric(
            radio_type="5g-nsa", cell_id=31, plmn="525-05",
            aka_failures_per_min=15.0,
        )
        snaps = db.nr_snapshots()
        assert {s.cell_id for s in snaps} == {30, 31}
    finally:
        db.close()


# -- CLI ingest ---------------------------------------------------------


def test_record_metric_cli(tmp_path: Path):
    db_path = tmp_path / "x.db"
    r = CliRunner().invoke(main, [
        "record-metric",
        "--db", str(db_path),
        "--radio-type", "2g",
        "--cell-id", "10",
        "--plmn", "525-05",
        "--cipher-mode", "A5/0",
        "--location-updates-per-min", "55",
    ])
    assert r.exit_code == 0, r.output
    assert json.loads(r.output)["recorded"] is True

    db = CaptureDB(db_path)
    try:
        snaps = db.gsm_snapshots()
        assert len(snaps) == 1
        assert snaps[0].cipher_mode == "A5/0"
        assert snaps[0].location_updates_per_min == 55.0
    finally:
        db.close()


# -- End-to-end: per-gen rule fires through CLI detect -----------------


def test_detect_fires_2g_a5_0_rule_after_metric_recorded(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        db.record_cell_metric(
            radio_type="2g", cell_id=10, plmn="525-05",
            cipher_mode="A5/0",
        )
    finally:
        db.close()

    r = CliRunner().invoke(main, [
        "detect", "--db", str(db_path),
        "--radio-type", "all",
    ])
    assert r.exit_code == 0
    rules = {a["rule"] for a in json.loads(r.output)}
    assert "gsm_a5_0_announced" in rules


def test_detect_fires_3g_rel99_rule(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        db.record_cell_metric(
            radio_type="3g", cell_id=20, plmn="525-05",
            advertises_rel99_only=True,
        )
    finally:
        db.close()

    r = CliRunner().invoke(main, [
        "detect", "--db", str(db_path), "--radio-type", "all",
    ])
    assert r.exit_code == 0
    rules = {a["rule"] for a in json.loads(r.output)}
    assert "umts_rel99_only" in rules


def test_detect_fires_5g_suci_replay_rule(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        db.record_cell_metric(
            radio_type="5g-sa", cell_id=30, plmn="525-05",
            suci_replays_per_min=20.0,
        )
    finally:
        db.close()

    r = CliRunner().invoke(main, [
        "detect", "--db", str(db_path), "--radio-type", "all",
    ])
    assert r.exit_code == 0
    rules = {a["rule"] for a in json.loads(r.output)}
    assert "nr_suci_replay" in rules


# -- Dashboard /api/anomalies includes per-gen rules -------------------


def test_dashboard_anomalies_includes_per_gen_rules(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        db.record_cell_metric(
            radio_type="2g", cell_id=10, plmn="525-05",
            cipher_mode="A5/0",
        )
    finally:
        db.close()

    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/anomalies?radio_type=all")
    assert r.status_code == 200
    rules = {a["rule"] for a in r.json()}
    assert "gsm_a5_0_announced" in rules


def test_detect_no_per_gen_rules_when_no_metrics(tmp_path: Path):
    """Sanity: an empty cell_metrics table doesn't fire per-gen rules."""
    db_path = tmp_path / "x.db"
    CaptureDB(db_path).close()
    r = CliRunner().invoke(main, [
        "detect", "--db", str(db_path), "--radio-type", "all",
    ])
    assert r.exit_code == 0
    out = json.loads(r.output)
    rules = {a["rule"] for a in out}
    # None of the per-gen rules should have fired.
    assert "gsm_a5_0_announced" not in rules
    assert "umts_rel99_only" not in rules
    assert "nr_suci_replay" not in rules
