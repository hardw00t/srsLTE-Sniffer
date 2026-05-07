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
def dashboard(db_path: str, port: int, host: str) -> None:
    """Serve the live dashboard."""
    import uvicorn

    from .dashboard import make_app
    app = make_app(db_path)
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
def detect(db_path: str, allowed_plmns: str, churn_threshold: int) -> None:
    """Run the rogue-eNB rules over the captured DB."""
    from .decoder import PagingRecord
    from .rogue_detector import CellSnapshot, run_all
    from .tracker import TimedPaging

    db = CaptureDB(db_path)
    try:
        cells_q = db._conn.execute(
            "SELECT cell_id, plmn, tac, si_periodicity FROM cells"
        ).fetchall()
        # paging_imsi_count / stmsi_count via subqueries
        cells: list[CellSnapshot] = []
        for cid, plmn, tac, sip in cells_q:
            ipage = db._conn.execute(
                "SELECT COUNT(*) FROM pagings WHERE cell_id=? AND kind='imsi'",
                (cid,),
            ).fetchone()[0]
            spage = db._conn.execute(
                "SELECT COUNT(*) FROM pagings WHERE cell_id=? AND kind='s-tmsi'",
                (cid,),
            ).fetchone()[0]
            cells.append(
                CellSnapshot(
                    cell_id=cid, plmn=plmn, tac=tac, si_periodicity=sip,
                    paging_imsi_count=ipage, paging_stmsi_count=spage,
                )
            )

        timeline_rows = db._conn.execute(
            "SELECT ts, kind, imsi, mmec, m_tmsi, cell_id FROM pagings"
        ).fetchall()
        timeline = [
            TimedPaging(
                record=PagingRecord(
                    kind=k, cn_domain=None,
                    imsi=imsi, mmec=mmec, m_tmsi=mtmsi,
                ),
                ts_us=ts, cell_id=cid,
            )
            for ts, k, imsi, mmec, mtmsi, cid in timeline_rows
        ]
        allowed = set(filter(None, allowed_plmns.split(","))) or None
        anomalies = run_all(cells, timeline, allowed_plmns=allowed,
                            churn_threshold=churn_threshold)
        click.echo(json.dumps(
            [a.__dict__ for a in anomalies],
            indent=2,
        ))
    finally:
        db.close()


@main.command("track")
@click.option("--db", "db_path", required=True)
@click.option("--window-ms", type=int, default=200, show_default=True)
def track_cmd(db_path: str, window_ms: int) -> None:
    """TMSI-correlation report."""
    from .decoder import PagingRecord
    from .tracker import TimedPaging, build_tracks

    db = CaptureDB(db_path)
    try:
        rows = db._conn.execute(
            "SELECT ts, kind, imsi, mmec, m_tmsi, cell_id FROM pagings "
            "WHERE imsi IS NOT NULL OR m_tmsi IS NOT NULL"
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
