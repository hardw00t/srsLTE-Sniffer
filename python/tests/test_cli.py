"""CLI smoke tests via Click's CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from srslte_sniffer.cli import main


def test_help():
    r = CliRunner().invoke(main, ["--help"])
    assert r.exit_code == 0
    assert "srsLTE-Sniffer" in r.output


def test_decode_subcommand_single_stmsi():
    r = CliRunner().invoke(
        main, ["decode", "40016c445a8200dabf6960450000"]
    )
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    assert out["ok"] is True
    assert len(out["records"]) == 1
    assert out["records"][0]["kind"] == "s-tmsi"
    assert out["records"][0]["mmec"] == 0x16


def test_analyze_subcommand_runs(tmp_path: Path, demo_txt):
    db_path = tmp_path / "out.db"
    r = CliRunner().invoke(main, [
        "analyze", str(demo_txt),
        "--db", str(db_path),
        "--earfcn", "1450",
        "--cell-id", "1",
    ])
    assert r.exit_code == 0, r.output
    stats = json.loads(r.output)
    assert stats["frames"] > 0
    assert db_path.exists()


def test_scan_refuses_without_authorization():
    r = CliRunner().invoke(main, [
        "scan", "--earfcns", "1450",
    ])
    # Click flags missing required option as exit 2
    assert r.exit_code != 0
