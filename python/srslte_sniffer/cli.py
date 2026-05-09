"""Click CLI — `srslte-sniffer <command>`.

Subcommands:

    analyze   <input> [--db captures.db]    — replace convert_to_csv
    dashboard --db captures.db [--port 8000]
    scan      <plan>                         — EARFCN sweep (uses external
                                               C sniffer, see dwell.sh)
    detect    --db captures.db               — run rogue-eNB rules
    track     --db captures.db               — TMSI tracker report
    decode    <hex>                          — one-shot decode of a paging PDU
    journal-replay <path> [--db]             — re-run analysis on a journal
"""

from __future__ import annotations

import json
import sys

import click

from . import LEGAL_BANNER
from .analyzer import analyze_file
from .db import CaptureDB
from .decoder import decode_pcch, extract_paging_records
from .journal import KIND_PCCH, KIND_SIB1, KIND_SIB2, replay


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option("2.0.0")
def main() -> None:
    """srsLTE-Sniffer v2 CLI."""


@main.command()
@click.argument("input_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--db", "db_path", default=None, help="Optional SQLite output.")
@click.option("--earfcn", type=int, default=None)
@click.option("--cell-id", type=int, default=None)
@click.option(
    "--unsafe-raw", is_flag=True,
    help="Store raw IMSI/M-TMSI instead of SHA-256 hashes. "
         "Requires written authorisation — see LEGAL.md.",
)
def analyze(input_path: str, db_path: str | None, earfcn: int | None,
            cell_id: int | None, unsafe_raw: bool) -> None:
    """Decode a capture file end-to-end (replaces convert_to_csv)."""
    stats = analyze_file(
        input_path,
        db_path=db_path,
        earfcn=earfcn,
        cell_id=cell_id,
        hash_identifiers=not unsafe_raw,
    )
    click.echo(json.dumps(stats.__dict__, indent=2))


@main.command()
@click.option("--db", "db_path", required=True)
@click.option("--port", default=8000, show_default=True)
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--geo-db", "geo_db_path", default=None,
              help="Optional OpenCellID-derived cache (see geo-import). "
                   "Required for the /cells/map page.")
@click.option("--auth-token", "auth_token", default=None,
              envvar="SRSLTE_DASHBOARD_TOKEN",
              help="Require X-Auth-Token header. Default: env "
                   "SRSLTE_DASHBOARD_TOKEN. None = open access.")
def dashboard(db_path: str, port: int, host: str,
              geo_db_path: str | None, auth_token: str | None) -> None:
    """Serve the live dashboard."""
    import uvicorn

    from .dashboard import make_app
    app = make_app(db_path, geo_db_path=geo_db_path, auth_token=auth_token)
    uvicorn.run(app, host=host, port=port, log_level="info")


@main.command()
@click.argument("hex_payload")
def decode(hex_payload: str) -> None:
    """Decode a single PCCH payload hex string."""
    buf = bytes.fromhex(hex_payload.replace(" ", "").replace("0x", ""))
    res = decode_pcch(buf)
    if not res.ok:
        click.echo(f"decode failed: {res.error}", err=True)
        sys.exit(1)
    out = {
        "ok": True,
        "records": [
            {
                "kind": r.kind,
                "imsi": r.imsi,
                "mmec": r.mmec,
                "m_tmsi": r.m_tmsi,
                "cn_domain": r.cn_domain,
            }
            for r in extract_paging_records(res)
        ],
    }
    click.echo(json.dumps(out, indent=2))


@main.command()
@click.option("--db", "db_path", required=True)
@click.option("--allowed-plmns", default="",
              help="Comma-separated allow-list, e.g. '525-01,525-02,525-03'")
@click.option("--churn-threshold", type=int, default=50, show_default=True)
@click.option("--radio-type", default="4g", show_default=True,
              help="Filter by radio_type. Use 'all' to include every "
                   "radio (LTE-tuned rules will produce false positives "
                   "on mixed DBs).")
def detect(db_path: str, allowed_plmns: str, churn_threshold: int,
           radio_type: str) -> None:
    """Run the rogue-eNB rules over the captured DB."""
    from .decoder import PagingRecord
    from .rogue_detector import CellSnapshot, run_all
    from .tracker import TimedPaging

    db = CaptureDB(db_path)
    try:
        if radio_type == "all":
            cell_q = ("SELECT cell_id, plmn, tac, si_periodicity "
                      "FROM cells")
            cell_args: tuple = ()
            page_q = ("SELECT ts, kind, imsi, mmec, m_tmsi, cell_id "
                      "FROM pagings")
            page_args: tuple = ()
            count_clause = ""
        else:
            cell_q = ("SELECT cell_id, plmn, tac, si_periodicity "
                      "FROM cells WHERE radio_type = ?")
            cell_args = (radio_type,)
            page_q = ("SELECT ts, kind, imsi, mmec, m_tmsi, cell_id "
                      "FROM pagings WHERE radio_type = ?")
            page_args = (radio_type,)
            count_clause = " AND radio_type = ?"

        cells_q = db._conn.execute(cell_q, cell_args).fetchall()
        cells: list[CellSnapshot] = []
        for cid, plmn, tac, sip in cells_q:
            count_args = (
                (cid, radio_type) if count_clause else (cid,)
            )
            ipage = db._conn.execute(
                f"SELECT COUNT(*) FROM pagings "
                f"WHERE cell_id=? AND kind='imsi'{count_clause}",
                count_args,
            ).fetchone()[0]
            spage = db._conn.execute(
                f"SELECT COUNT(*) FROM pagings "
                f"WHERE cell_id=? AND kind='s-tmsi'{count_clause}",
                count_args,
            ).fetchone()[0]
            cells.append(
                CellSnapshot(
                    cell_id=cid, plmn=plmn, tac=tac, si_periodicity=sip,
                    paging_imsi_count=ipage, paging_stmsi_count=spage,
                )
            )

        timeline = [
            TimedPaging(
                record=PagingRecord(
                    kind=k, cn_domain=None,
                    imsi=imsi, mmec=mmec, m_tmsi=mtmsi,
                ),
                ts_us=ts, cell_id=cid,
            )
            for ts, k, imsi, mmec, mtmsi, cid in db._conn.execute(
                page_q, page_args
            ).fetchall()
        ]
        allowed = set(filter(None, allowed_plmns.split(","))) or None
        # Build per-generation snapshots from cell_metrics so 2G/3G/5G
        # rules fire when external ingesters have populated the table.
        anomalies = run_all(
            cells, timeline,
            allowed_plmns=allowed,
            churn_threshold=churn_threshold,
            gsm_cells=db.gsm_snapshots() or None,
            umts_cells=db.umts_snapshots() or None,
            nr_cells=db.nr_snapshots() or None,
        )
        click.echo(json.dumps(
            [a.__dict__ for a in anomalies],
            indent=2,
        ))
    finally:
        db.close()


@main.command("track")
@click.option("--db", "db_path", required=True)
@click.option("--window-ms", type=int, default=200, show_default=True)
@click.option("--radio-type", default="4g", show_default=True,
              help="Filter by radio_type. 'all' for every radio. "
                   "Note: track is LTE-shaped — for 2G/3G/5G use `move`.")
def track_cmd(db_path: str, window_ms: int, radio_type: str) -> None:
    """TMSI-correlation report.

    This command is LTE-shaped: it uses 4G IMSI / M-TMSI fields only.
    For non-4G radios (which carry their identifiers in different DB
    columns) it'll silently miss tracks — so we redirect to ``move``
    automatically and tell the user.
    """
    from .decoder import PagingRecord
    from .tracker import TimedPaging, build_tracks

    if radio_type not in ("4g", "all"):
        # `track` cannot see 2G TMSI / 3G P-TMSI / 5G ng-5G-S-TMSI (the
        # build_tracks input is PagingRecord-shaped). Tell the user
        # explicitly and run the cross-radio analyser instead.
        click.echo(
            f"# `track` is LTE-only; --radio-type={radio_type} routes to `move` "
            f"(cross-radio mobility correlator). Use `srslte-sniffer move` "
            f"directly to skip this notice.",
            err=True,
        )
        from .hub import correlate_subscriber_movement

        db = CaptureDB(db_path)
        try:
            window_s = max(1, (window_ms + 999) // 1000)
            click.echo(json.dumps(
                correlate_subscriber_movement(db, window_s=window_s),
                indent=2,
            ))
        finally:
            db.close()
        return

    db = CaptureDB(db_path)
    try:
        if radio_type == "all":
            rows = db._conn.execute(
                "SELECT ts, kind, imsi, mmec, m_tmsi, cell_id FROM pagings "
                "WHERE imsi IS NOT NULL OR m_tmsi IS NOT NULL"
            ).fetchall()
        else:
            rows = db._conn.execute(
                "SELECT ts, kind, imsi, mmec, m_tmsi, cell_id FROM pagings "
                "WHERE radio_type = ? "
                "AND (imsi IS NOT NULL OR m_tmsi IS NOT NULL)",
                (radio_type,),
            ).fetchall()
        timeline = [
            TimedPaging(
                record=PagingRecord(
                    kind=k, cn_domain=None,
                    imsi=imsi, mmec=mmec, m_tmsi=mtmsi,
                ),
                ts_us=ts,
                cell_id=cid,
            )
            for ts, k, imsi, mmec, mtmsi, cid in rows
        ]
        tracks = build_tracks(timeline, window_us=window_ms * 1000)
        out = [
            {
                "imsi": t.imsi,
                "pages": t.pages,
                "cells": sorted(t.cells),
                "stmsi_seen": [list(s) for s in t.seen_stmsis],
                "first_ts": t.first_ts,
                "last_ts": t.last_ts,
            }
            for t in tracks
        ]
        click.echo(json.dumps(out, indent=2))
    finally:
        db.close()


@main.command("move")
@click.option("--db", "db_path", required=True)
@click.option("--window-s", type=int, default=300, show_default=True)
def move_cmd(db_path: str, window_s: int) -> None:
    """Cross-radio mobility report — same identifier seen on multiple cells.

    Handles every radio_type's identifiers (IMSI / TMSI / M-TMSI / P-TMSI /
    ng-5G-S-TMSI). An IMSI appearing on both 2G and 4G correlates as the
    same subscriber via the IMSI key.
    """
    from .hub import correlate_subscriber_movement

    db = CaptureDB(db_path)
    try:
        movements = correlate_subscriber_movement(db, window_s=window_s)
        click.echo(json.dumps(movements, indent=2))
    finally:
        db.close()


@main.command("journal-replay")
@click.argument("journal_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--db", "db_path", default=None)
def journal_replay(journal_path: str, db_path: str | None) -> None:
    """Re-decode a crash-safe journal into the analyzer."""
    from .analyzer import analyze_frames
    from .pcap_io import PAGING_HEADER, SIB1_HEADER, SIB2_HEADER, CapturedFrame

    def _frames():
        for kind, ts_us, payload in replay(journal_path):
            if kind == KIND_PCCH:
                framing = "pcch"
                header = PAGING_HEADER
            elif kind == KIND_SIB1:
                framing = "sib1"
                header = SIB1_HEADER
            elif kind == KIND_SIB2:
                framing = "sib2"
                header = SIB2_HEADER
            else:
                framing = "unknown"
                header = b""
            yield CapturedFrame(
                payload=payload, raw=header + payload,
                framing=framing, timestamp_us=ts_us,
            )

    db = CaptureDB(db_path) if db_path else None
    try:
        stats = analyze_frames(_frames(), db=db)
        click.echo(json.dumps(stats.__dict__, indent=2))
    finally:
        if db:
            db.close()


@main.command()
@click.argument("journal_path", type=click.Path(dir_okay=False))
@click.option("--db", "db_path", default=None,
              help="Optional SQLite store updated as records arrive.")
@click.option("--workers", type=int, default=2, show_default=True)
@click.option("--queue-size", type=int, default=1024, show_default=True)
def stream(journal_path: str, db_path: str | None,
           workers: int, queue_size: int) -> None:
    """Tail a journal in real time, decode, print JSON-lines.

    Pair with `dashboard --stream-journal` to push events to the WS feed.
    """
    import asyncio
    import sys

    from .streaming import StreamingPipeline

    pipeline = StreamingPipeline(
        journal_path,
        decoder_workers=workers,
        queue_size=queue_size,
    )

    db = CaptureDB(db_path) if db_path else None

    def on_event(ev) -> None:
        line = {
            "ts_us": ev.ts_us, "kind": ev.kind, "ok": ev.decode_ok,
            "records": [
                {"kind": r.kind, "imsi": r.imsi,
                 "mmec": r.mmec, "m_tmsi": r.m_tmsi}
                for r in ev.records
            ],
        }
        click.echo(json.dumps(line))
        sys.stdout.flush()
        if db:
            for r in ev.records:
                db.insert_paging(r.hashed())

    pipeline.subscribe(on_event)
    try:
        asyncio.run(pipeline.run())
    except KeyboardInterrupt:
        pass
    finally:
        if db:
            db.close()


@main.command()
@click.argument("capture_path", type=click.Path(exists=True, dir_okay=False))
@click.argument("journal_path", type=click.Path(dir_okay=False))
@click.option("--rate", type=float, default=100.0, show_default=True,
              help="Records/sec to write. 0 = as fast as possible.")
@click.option("--limit", type=int, default=None,
              help="Stop after N records. Default: replay everything.")
def simulate(capture_path: str, journal_path: str,
             rate: float, limit: int | None) -> None:
    """Replay a saved capture into a journal — drives streaming end-to-end
    without RF kit. Useful for demos, integration tests, dashboard bring-up.
    """
    from .simulator import replay_sync

    n = replay_sync(capture_path, journal_path, rate_hz=rate, limit=limit)
    click.echo(f"wrote {n} records to {journal_path}")


@main.command()
@click.option("--db", "db_path", required=True)
@click.option("--port", default=9100, show_default=True)
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--journal", "journal_path", default=None,
              help="Optional journal to tail for live metrics.")
def metrics(db_path: str, port: int, host: str,
            journal_path: str | None) -> None:
    """Serve Prometheus metrics on /metrics.

    With ``--journal`` the metrics include live pipeline counters; without
    it they reflect snapshot-on-scrape DB state.
    """
    import asyncio
    import threading

    import uvicorn

    from .metrics import Metrics, make_metrics_app
    from .streaming import StreamingPipeline

    m = Metrics()
    pipeline = None
    if journal_path:
        pipeline = StreamingPipeline(journal_path)
        m.bind_pipeline(pipeline)
        loop = asyncio.new_event_loop()

        def _runner() -> None:
            asyncio.set_event_loop(loop)
            loop.run_until_complete(pipeline.run())

        threading.Thread(target=_runner, daemon=True).start()

    app = make_metrics_app(m)
    uvicorn.run(app, host=host, port=port, log_level="info")


@main.command()
@click.argument("src", type=click.Path(exists=True, dir_okay=False))
@click.argument("dst", type=click.Path(dir_okay=False))
@click.option("--preserve-mcc/--no-preserve-mcc", default=True,
              show_default=True,
              help="Keep MCC in IMSIs (network-shape preserved).")
def redact(src: str, dst: str, preserve_mcc: bool) -> None:
    """Rewrite a capture replacing IMSI/M-TMSI with hash-derived dummies."""
    from .redact import redact_capture

    stats = redact_capture(src, dst, preserve_mcc=preserve_mcc)
    click.echo(json.dumps(stats.__dict__, indent=2))


@main.command()
@click.option("--db", "db_path", required=True)
@click.option("--older-than", "older_than", required=True,
              help="Delete records older than this duration "
                   "(e.g. '30d', '12h', '7200s').")
def prune(db_path: str, older_than: str) -> None:
    """Delete records older than a duration. SQLite VACUUMs after."""
    import re
    import time

    m = re.fullmatch(r"\s*(\d+)\s*([smhd])\s*", older_than)
    if not m:
        click.echo("--older-than format: <int>(s|m|h|d), e.g. 30d", err=True)
        raise click.exceptions.Exit(1)
    n = int(m.group(1))
    unit = m.group(2)
    seconds = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    cutoff_us = int((time.time() - n * seconds) * 1e6)

    db = CaptureDB(db_path)
    try:
        result = db.prune_older_than(cutoff_us)
        click.echo(json.dumps(result, indent=2))
    finally:
        db.close()


@main.command()
@click.option("--config-dir", default="~/.srslte", show_default=True)
def init(config_dir: str) -> None:
    """Set up a sane working directory: config, demo decode, dashboard hint.

    Removes the 'where do I start?' friction. Idempotent.
    """
    import os
    from pathlib import Path

    target = Path(os.path.expanduser(config_dir))
    target.mkdir(parents=True, exist_ok=True)

    cfg = target / "config.toml"
    if not cfg.exists():
        cfg.write_text(
            "# srsLTE-Sniffer config — edit to taste.\n"
            "[capture]\n"
            "earfcns = [1300, 1600]\n"
            "dwell_seconds = 240\n\n"
            "[dashboard]\n"
            "host = \"127.0.0.1\"\n"
            "port = 8000\n"
            "# auth_token = \"set me\"  # uncomment to require X-Auth-Token\n\n"
            "[storage]\n"
            "db = \"~/.srslte/captures.db\"\n"
            "journal_dir = \"~/.srslte/journals\"\n"
        )

    journals = target / "journals"
    journals.mkdir(exist_ok=True)

    # Pre-seed by running the analyzer over the included demo capture if
    # we can find it.
    demo_paths = [
        Path("Output Files") / "imsi.pcap",
        Path("imsi_pcap_demo.txt"),
    ]
    seeded = False
    for p in demo_paths:
        if p.exists():
            db_path = target / "captures.db"
            from .analyzer import analyze_file
            stats = analyze_file(str(p), db_path=str(db_path))
            click.echo(f"Seeded demo capture from {p}: "
                       f"{stats.pagings_total} pagings into {db_path}")
            seeded = True
            break

    click.echo(json.dumps({
        "config_dir": str(target),
        "config_file": str(cfg),
        "journals_dir": str(journals),
        "seeded": seeded,
        "next": [
            f"srslte-sniffer dashboard --db {target}/captures.db",
            "open http://127.0.0.1:8000",
            "see docs/USAGE.md for capture mode",
        ],
    }, indent=2))


@main.command()
@click.option("--db", "db_path", required=True)
@click.option("--port", default=9200, show_default=True)
@click.option("--host", default="0.0.0.0", show_default=True)
@click.option("--auth-token", "auth_token", default=None,
              envvar="SRSLTE_HUB_TOKEN",
              help="Required Bearer token for /ingest. "
                   "Default: env SRSLTE_HUB_TOKEN.")
def hub(db_path: str, port: int, host: str,
        auth_token: str | None) -> None:
    """Run the multi-node aggregation hub (receives pushes from sniffers)."""
    import uvicorn

    from .hub import make_hub_app
    app = make_hub_app(db_path, auth_token=auth_token)
    uvicorn.run(app, host=host, port=port, log_level="info")


@main.command("record-metric")
@click.option("--db", "db_path", required=True)
@click.option("--radio-type", required=True,
              type=click.Choice(["2g", "3g", "4g", "5g-nsa", "5g-sa"]))
@click.option("--cell-id", type=int, required=True)
@click.option("--plmn", default=None)
@click.option("--arfcn", type=int, default=None)
@click.option("--cipher-mode", default=None,
              help="2G only: A5/0, A5/1, A5/3.")
@click.option("--location-updates-per-min", type=float, default=None,
              help="2G only.")
@click.option("--rrc-reject-per-min", type=float, default=None,
              help="3G only.")
@click.option("--rel99-only/--no-rel99-only", "rel99_only",
              default=None, help="3G only.")
@click.option("--suci-replays-per-min", type=float, default=None,
              help="5G only.")
@click.option("--aka-failures-per-min", type=float, default=None,
              help="5G only.")
def record_metric(
    db_path: str, radio_type: str, cell_id: int,
    plmn: str | None, arfcn: int | None,
    cipher_mode: str | None,
    location_updates_per_min: float | None,
    rrc_reject_per_min: float | None,
    rel99_only: bool | None,
    suci_replays_per_min: float | None,
    aka_failures_per_min: float | None,
) -> None:
    """Upsert a per-cell metric used by the per-generation rogue rules.

    Fields left unset preserve their previous value. Designed for
    external monitoring scripts to feed counters that the capture
    binaries don't track today (cipher mode, AKA failures, etc.).
    """
    db = CaptureDB(db_path)
    try:
        db.record_cell_metric(
            radio_type=radio_type, cell_id=cell_id, plmn=plmn,
            arfcn=arfcn, cipher_mode=cipher_mode,
            location_updates_per_min=location_updates_per_min,
            rrc_reject_per_min=rrc_reject_per_min,
            advertises_rel99_only=rel99_only,
            suci_replays_per_min=suci_replays_per_min,
            aka_failures_per_min=aka_failures_per_min,
        )
        click.echo(json.dumps({"recorded": True,
                               "radio_type": radio_type,
                               "cell_id": cell_id, "plmn": plmn},
                              indent=2))
    finally:
        db.close()


@main.command("geo-import")
@click.argument("csv_path", type=click.Path(exists=True, dir_okay=False))
@click.option("--db", "geo_db", default="cell_geo.db", show_default=True)
def geo_import(csv_path: str, geo_db: str) -> None:
    """Load an OpenCellID-format CSV into the geo cache."""
    from .geo import GeoCache

    cache = GeoCache(geo_db)
    try:
        n = cache.import_opencellid_csv(csv_path)
        click.echo(json.dumps({"imported": n,
                               "total_in_cache": cache.count()},
                              indent=2))
    finally:
        cache.close()


@main.command()
@click.option("--earfcns", required=True,
              help="Comma-separated EARFCN list, e.g. 1450,1750")
@click.option("--dwell", type=float, default=60.0, show_default=True)
@click.option("--cycles", type=int, default=1, show_default=True)
@click.option("--dwell-script",
              default="./scripts/dwell.sh",
              show_default=True,
              help="External dwell script that takes EARFCN and dwell-seconds "
                   "and writes a journal segment.")
@click.option("--i-have-authorization", is_flag=True, required=True)
def scan(earfcns: str, dwell: float, cycles: int,
         dwell_script: str, i_have_authorization: bool) -> None:
    """Sweep EARFCNs and capture (requires SDR + authorisation)."""
    if not i_have_authorization:
        click.echo("Refusing — see LEGAL.md.", err=True)
        sys.exit(2)
    click.echo(LEGAL_BANNER, err=True)
    import subprocess

    from .scanner import CellObservation, Scanner, ScanPlan

    plan = ScanPlan(
        earfcns=[int(x) for x in earfcns.split(",") if x.strip()],
        dwell_seconds=dwell,
        max_cycles=cycles,
    )

    def _dwell(earfcn: int, hz: int, seconds: float) -> CellObservation:
        try:
            subprocess.run(
                [dwell_script, str(earfcn), str(hz), str(seconds)],
                check=True, timeout=seconds + 30,
            )
            return CellObservation(earfcn=earfcn, hz=hz, locked=True)
        except subprocess.CalledProcessError as e:
            return CellObservation(earfcn=earfcn, hz=hz, locked=False,
                                   error=str(e))

    for obs in Scanner(plan, _dwell).run():
        click.echo(json.dumps(obs.__dict__))


if __name__ == "__main__":
    main()
