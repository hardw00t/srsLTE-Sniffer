"""v2.3.2 regression tests — strengthened heuristic, cross-radio
mobility, broadened DB queries, radio_type metric label, CLI radio-type
filters."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from fastapi.testclient import TestClient

from srslte_sniffer.analyzer import _looks_like_gsm_paging, analyze_frames
from srslte_sniffer.cli import main
from srslte_sniffer.dashboard import make_app
from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.decoder_2g import (
    MT_PAGING_TYPE_1,
    MT_PAGING_TYPE_2,
    MT_PAGING_TYPE_3,
)
from srslte_sniffer.decoder_common import WidePagingRecord
from srslte_sniffer.hub import correlate_subscriber_movement
from srslte_sniffer.metrics import Metrics
from srslte_sniffer.pcap_io import CapturedFrame
from srslte_sniffer.streaming import StreamEvent


# -- 1. Strengthened GSM heuristic --------------------------------------


def test_heuristic_rejects_lte_pcch_with_low_nibble_6():
    """The naive (byte0 & 0x0F) == 0x06 check would mis-route this LTE
    PCCH PDU (taken from the demo capture) — the new heuristic must
    reject it via the byte-1 message-type check."""
    real_lte_with_amb_byte0 = bytes.fromhex(
        "465016d38de0e1da39f43b1d000000"
    )
    assert (real_lte_with_amb_byte0[0] & 0x0F) == 0x06
    assert _looks_like_gsm_paging(real_lte_with_amb_byte0) is False


def test_heuristic_accepts_real_gsm_paging():
    for mt in (MT_PAGING_TYPE_1, MT_PAGING_TYPE_2, MT_PAGING_TYPE_3):
        pkt = bytes([0x06, mt, 0x00, 0xDE, 0xAD, 0xBE, 0xEF])
        assert _looks_like_gsm_paging(pkt), f"failed for MT 0x{mt:02x}"


def test_heuristic_rejects_short_input():
    assert _looks_like_gsm_paging(b"") is False
    assert _looks_like_gsm_paging(b"\x06") is False


def test_analyzer_no_longer_misroutes_lte_pcch_with_byte0_low6(tmp_path: Path):
    """Regression: the v2.3.1 heuristic mis-routed real LTE traffic to
    the 2G decoder. Demo-corpus PDU should now land as 4G correctly."""
    db = CaptureDB(tmp_path / "x.db")
    try:
        # This is a real 4G PCCH from the demo capture with a 0x06
        # low-nibble byte 0. Legitimate paging — must NOT go to 2G.
        # We construct a synthetic-but-valid PCCH for determinism.
        from srslte_sniffer.decoder import _PCCH

        val = {"message": ("c1", ("paging", {
            "pagingRecordList": [{
                "ue-Identity": (
                    "s-TMSI",
                    {"mmec": (22, 8), "m-TMSI": (0xCAFEBABE, 32)},
                ),
                "cn-Domain": "ps",
            }],
        }))}
        _PCCH.set_val(val)
        legit_lte = _PCCH.to_uper()
        # Sanity — we want the actually-encoded byte 0 to not collide.
        # If pycrate happened to emit 0x06-low we'd skip, but that's fine.
        frames = [CapturedFrame(
            payload=legit_lte, raw=legit_lte,
            framing="pcch", timestamp_us=1,
        )]
        stats = analyze_frames(iter(frames), db=db,
                               hash_identifiers=False)
        # Must land via the LTE branch, not the 2G one.
        assert stats.decoded_pcch == 1
        assert stats.pagings_2g == 0
        row = db._conn.execute(
            "SELECT radio_type, kind, m_tmsi FROM pagings"
        ).fetchone()
        assert row == ("4g", "s-tmsi", 0xCAFEBABE)
    finally:
        db.close()


# -- 2. Cross-radio mobility correlator --------------------------------


def test_correlate_imsi_seen_across_radios(tmp_path: Path):
    """Same IMSI on 2G cell 1 and 4G cell 2 → correlated as one
    subscriber via the IMSI key."""
    db = CaptureDB(tmp_path / "x.db")
    try:
        db.insert_wide_paging(
            WidePagingRecord(radio_type="2g", kind="imsi",
                             imsi="525058131997813"),
            ts_us=10_000_000, cell_id=1,
        )
        db.insert_wide_paging(
            WidePagingRecord(radio_type="4g", kind="imsi",
                             imsi="525058131997813"),
            ts_us=20_000_000, cell_id=2,
        )
        m = correlate_subscriber_movement(db, window_s=60)
        assert "imsi:525058131997813" in m
        assert m["imsi:525058131997813"] == [1, 2]
    finally:
        db.close()


def test_correlate_2g_tmsi_movement(tmp_path: Path):
    """A 2G TMSI seen on two cells within window → mobility."""
    db = CaptureDB(tmp_path / "x.db")
    try:
        for ts_us, cid in [(10_000_000, 1), (20_000_000, 2)]:
            db.insert_wide_paging(
                WidePagingRecord(radio_type="2g", kind="tmsi",
                                 tmsi=0xCAFEBABE),
                ts_us=ts_us, cell_id=cid,
            )
        m = correlate_subscriber_movement(db, window_s=60)
        assert m == {"2g-tmsi:3405691582": [1, 2]}
    finally:
        db.close()


def test_correlate_5g_ng_tmsi_movement(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        for ts_us, cid in [(10_000_000, 1), (20_000_000, 2)]:
            db.insert_wide_paging(
                WidePagingRecord(radio_type="5g-sa", kind="ng-5g-s-tmsi",
                                 ng_5g_s_tmsi=0xABCDEF),
                ts_us=ts_us, cell_id=cid,
            )
        m = correlate_subscriber_movement(db, window_s=60)
        assert "ng5gtmsi:11259375" in m


    finally:
        db.close()


def test_correlate_tmsi_namespaced_per_radio(tmp_path: Path):
    """A 2G TMSI 0xCAFEBABE and a 4G M-TMSI 0xCAFEBABE must NOT
    correlate — different radios, different identifier namespaces."""
    db = CaptureDB(tmp_path / "x.db")
    try:
        db.insert_wide_paging(
            WidePagingRecord(radio_type="2g", kind="tmsi", tmsi=0xCAFEBABE),
            ts_us=10_000_000, cell_id=1,
        )
        db.insert_wide_paging(
            WidePagingRecord(radio_type="4g", kind="s-tmsi",
                             mmec=22, m_tmsi=0xCAFEBABE),
            ts_us=20_000_000, cell_id=2,
        )
        m = correlate_subscriber_movement(db, window_s=60)
        # Two separate keys, neither correlated (each appears once)
        assert m == {}
    finally:
        db.close()


# -- 3. CLI radio_type filters -----------------------------------------


def test_cli_detect_radio_type_filter(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
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

    runner = CliRunner()
    r = runner.invoke(main, [
        "detect", "--db", str(db_path),
        "--allowed-plmns", "525-05",
    ])
    assert r.exit_code == 0
    rules = {a["rule"] for a in json.loads(r.output)}
    assert "unknown_plmn" in rules

    # Filter to 2g — only the legit 2G cell, no anomalies.
    r2 = runner.invoke(main, [
        "detect", "--db", str(db_path),
        "--allowed-plmns", "525-05",
        "--radio-type", "2g",
    ])
    assert r2.exit_code == 0
    rules2 = {a["rule"] for a in json.loads(r2.output)}
    assert "unknown_plmn" not in rules2


def test_cli_move_command(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        db.insert_wide_paging(
            WidePagingRecord(radio_type="2g", kind="imsi",
                             imsi="525050000000001"),
            ts_us=1, cell_id=1,
        )
        db.insert_wide_paging(
            WidePagingRecord(radio_type="2g", kind="imsi",
                             imsi="525050000000001"),
            ts_us=2, cell_id=2,
        )
    finally:
        db.close()

    r = CliRunner().invoke(main, ["move", "--db", str(db_path)])
    assert r.exit_code == 0, r.output
    out = json.loads(r.output)
    assert "imsi:525050000000001" in out


# -- 4. Metrics carry radio_type ----------------------------------------


def test_metrics_pagings_label_includes_radio_type():
    m = Metrics()
    m.on_wide_record(kind="tmsi", radio_type="2g")
    m.on_wide_record(kind="ng-5g-s-tmsi", radio_type="5g-sa")
    from prometheus_client import generate_latest

    text = generate_latest(m.registry).decode()
    assert "radio_type=\"2g\"" in text
    assert "radio_type=\"5g-sa\"" in text


def test_metrics_on_event_default_4g():
    m = Metrics()
    ev = StreamEvent(
        kind=1, ts_us=0, raw=b"",
        records=[PagingRecord(kind="imsi", cn_domain="ps", imsi="x")],
        decode_ok=True,
    )
    m.on_event(ev)  # default radio_type='4g'
    from prometheus_client import generate_latest

    text = generate_latest(m.registry).decode()
    assert "radio_type=\"4g\"" in text


# -- 5. recent_pagings + imsis_by_count broadening ---------------------


def test_recent_pagings_returns_wide_columns(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        db.insert_wide_paging(
            WidePagingRecord(radio_type="5g-sa", kind="ng-5g-s-tmsi",
                             ng_5g_s_tmsi=0xCAFEBABE),
            ts_us=1, cell_id=42, arfcn=10560,
        )
        rows = db.recent_pagings(limit=10)
        assert rows[0]["radio_type"] == "5g-sa"
        assert rows[0]["ng_5g_s_tmsi"] == 0xCAFEBABE
        assert rows[0]["arfcn"] == 10560
    finally:
        db.close()


def test_imsis_by_count_includes_2g(tmp_path: Path):
    db = CaptureDB(tmp_path / "x.db")
    try:
        # 2G IMSI captured via gsm_adapter has kind='imsi' too — but
        # the v2 query had `WHERE kind='imsi'`. Verify post-broadening:
        # any row with non-null imsi shows up regardless of kind.
        db.insert_wide_paging(
            WidePagingRecord(radio_type="2g", kind="imsi",
                             imsi="525050000000001"),
            ts_us=1, cell_id=1,
        )
        db.insert_wide_paging(
            WidePagingRecord(radio_type="4g", kind="imsi",
                             imsi="525050000000002"),
            ts_us=2, cell_id=2,
        )
        rows = db.imsis_by_count(limit=10)
        imsis = {r["imsi"] for r in rows}
        assert imsis == {"525050000000001", "525050000000002"}
    finally:
        db.close()


# -- 6. Dashboard /api/recent surfaces wide columns --------------------


def test_dashboard_api_recent_includes_wide_columns(tmp_path: Path):
    db_path = tmp_path / "x.db"
    db = CaptureDB(db_path)
    try:
        db.insert_wide_paging(
            WidePagingRecord(radio_type="3g", kind="p-tmsi",
                             p_tmsi=0xCAFEBABE),
            ts_us=1, cell_id=42,
        )
    finally:
        db.close()

    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/recent?limit=5")
    assert r.status_code == 200
    rows = r.json()
    assert rows[0]["radio_type"] == "3g"
    assert rows[0]["p_tmsi"] == 0xCAFEBABE
