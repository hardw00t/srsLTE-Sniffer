"""Live dashboard — FastAPI + HTMX. No React, no build step.

Run:  srslte-sniffer dashboard --db captures.db --port 8000

Renders:
    /            — overview (counts, recent pagings)
    /imsis       — IMSI leaderboard with first/last seen
    /api/stats   — JSON for HTMX polling
    /ws          — live WebSocket stream of decoded events when a journal
                   is being tailed (see `srslte-sniffer stream`)
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import json
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .db import CaptureDB
from .streaming import StreamEvent, StreamingPipeline

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
)


def _fmt_ts(us: int | None) -> str:
    if us is None:
        return ""
    try:
        return _dt.datetime.fromtimestamp(us / 1e6).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(us)


class _Hub:
    """In-process pub/sub for WebSocket clients. Each `StreamingPipeline`
    publishes to it; each WS client subscribes for its lifetime."""

    def __init__(self) -> None:
        self._subs: set[asyncio.Queue[str]] = set()

    def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(256)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        self._subs.discard(q)

    def publish(self, ev: StreamEvent) -> None:
        msg = json.dumps(
            {
                "ts_us": ev.ts_us,
                "kind": ev.kind,
                "decode_ok": ev.decode_ok,
                "records": [
                    {
                        "kind": r.kind,
                        "imsi": r.imsi,
                        "mmec": r.mmec,
                        "m_tmsi": r.m_tmsi,
                    }
                    for r in ev.records
                ],
            }
        )
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                # Slow client — drop the message.
                pass


def make_app(
    db_path: str,
    *,
    pipeline: StreamingPipeline | None = None,
    geo_db_path: str | None = None,
    auth_token: str | None = None,
) -> FastAPI:
    app = FastAPI(title="srsLTE-Sniffer dashboard", version="2.0.0")
    hub = _Hub()
    if pipeline is not None:
        pipeline.subscribe(hub.publish)

    if auth_token:
        from fastapi import Request
        from fastapi.responses import PlainTextResponse

        @app.middleware("http")
        async def _auth(request: Request, call_next):
            # Allow the WS handshake to be authenticated via query string
            # since browser WebSocket can't easily set custom headers.
            if request.url.path == "/ws":
                token = request.query_params.get("token")
            else:
                token = request.headers.get("x-auth-token")
            if token != auth_token:
                return PlainTextResponse("unauthorized", status_code=401)
            return await call_next(request)

    def _db() -> CaptureDB:
        return CaptureDB(db_path)

    def _geo():
        if not geo_db_path:
            return None
        from .geo import GeoCache
        return GeoCache(geo_db_path)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        db = _db()
        try:
            stats = db.stats()
            recent = db.recent_pagings(20)
            for r in recent:
                r["ts_str"] = _fmt_ts(r.get("ts"))
            return _env.get_template("dashboard.html").render(
                stats=stats, recent=recent,
                streaming=pipeline is not None,
            )
        finally:
            db.close()

    @app.get("/imsis", response_class=HTMLResponse)
    def imsis() -> str:
        db = _db()
        try:
            top = db.imsis_by_count(50)
            for r in top:
                r["first_str"] = _fmt_ts(r.get("first_seen"))
                r["last_str"] = _fmt_ts(r.get("last_seen"))
            return _env.get_template("imsis.html").render(rows=top)
        finally:
            db.close()

    @app.get("/api/stats")
    def stats_json():
        db = _db()
        try:
            data = db.stats()
            if pipeline is not None:
                data["pipeline_processed"] = pipeline.processed
                data["pipeline_dropped"] = pipeline.dropped
            return JSONResponse(data)
        finally:
            db.close()

    @app.get("/api/recent")
    def recent_json(limit: int = 50):
        db = _db()
        try:
            return JSONResponse(db.recent_pagings(limit))
        finally:
            db.close()

    @app.get("/api/timeseries")
    def timeseries(bucket_seconds: int = 60, limit: int = 200):
        """Bucket recent paging counts by time. Drives the sparkline on the
        index page; also useful for any external consumer."""
        bucket_us = bucket_seconds * 1_000_000
        db = _db()
        try:
            rows = db._conn.execute(
                "SELECT (ts / ?) AS bucket, kind, COUNT(*) AS n "
                "FROM pagings GROUP BY bucket, kind "
                "ORDER BY bucket DESC LIMIT ?",
                (bucket_us, limit),
            ).fetchall()
            out: dict[int, dict[str, int]] = {}
            for bucket, kind, n in rows:
                out.setdefault(bucket * bucket_seconds, {})[kind] = n
            return JSONResponse({
                "bucket_seconds": bucket_seconds,
                "series": [
                    {"ts_seconds": ts, "counts": counts}
                    for ts, counts in sorted(out.items())
                ],
            })
        finally:
            db.close()

    @app.get("/cells/map", response_class=HTMLResponse)
    def cells_map() -> str:
        """Leaflet map of observed cells. Joins captures.cells with the
        OpenCellID-derived cell_geo table."""
        db = _db()
        geo = _geo()
        try:
            cells_q = db._conn.execute(
                "SELECT cell_id, plmn, tac FROM cells WHERE cell_id IS NOT NULL"
            ).fetchall()
            features = []
            unmatched = 0
            for cid, plmn, tac in cells_q:
                if not (geo and plmn and tac):
                    unmatched += 1
                    continue
                try:
                    mcc, mnc = plmn.split("-")
                    loc = geo.lookup(int(mcc), int(mnc), int(tac), int(cid))
                    if loc:
                        features.append({
                            "cell_id": cid, "plmn": plmn, "tac": tac,
                            "lon": loc.lon, "lat": loc.lat,
                            "accuracy_m": loc.accuracy_m,
                        })
                    else:
                        unmatched += 1
                except (ValueError, TypeError):
                    unmatched += 1
            return _env.get_template("cells_map.html").render(
                features=features, unmatched=unmatched,
                geo_db_set=(geo is not None),
            )
        finally:
            db.close()
            if geo:
                geo.close()

    @app.get("/api/anomalies")
    def anomalies(allowed_plmns: str | None = None):
        """Run the rogue-eNB rules over the current DB snapshot."""
        from .decoder import PagingRecord
        from .rogue_detector import CellSnapshot, run_all
        from .tracker import TimedPaging

        db = _db()
        try:
            cells = []
            for cid, plmn, tac, sip in db._conn.execute(
                "SELECT cell_id, plmn, tac, si_periodicity FROM cells"
            ).fetchall():
                ipage = db._conn.execute(
                    "SELECT COUNT(*) FROM pagings WHERE cell_id=? AND kind='imsi'",
                    (cid,),
                ).fetchone()[0]
                spage = db._conn.execute(
                    "SELECT COUNT(*) FROM pagings WHERE cell_id=? AND kind='s-tmsi'",
                    (cid,),
                ).fetchone()[0]
                cells.append(CellSnapshot(
                    cell_id=cid, plmn=plmn, tac=tac, si_periodicity=sip,
                    paging_imsi_count=ipage, paging_stmsi_count=spage,
                ))
            timeline = [
                TimedPaging(
                    record=PagingRecord(
                        kind=k, cn_domain=None,
                        imsi=imsi, mmec=mmec, m_tmsi=mtmsi,
                    ),
                    ts_us=ts, cell_id=cid,
                )
                for ts, k, imsi, mmec, mtmsi, cid in db._conn.execute(
                    "SELECT ts, kind, imsi, mmec, m_tmsi, cell_id FROM pagings"
                ).fetchall()
            ]
            allowed = (
                set(filter(None, allowed_plmns.split(",")))
                if allowed_plmns else None
            )
            results = run_all(cells, timeline, allowed_plmns=allowed)
            return JSONResponse([a.__dict__ for a in results])
        finally:
            db.close()

    @app.websocket("/ws")
    async def ws_endpoint(ws: WebSocket) -> None:
        await ws.accept()
        q = hub.subscribe()
        try:
            while True:
                msg = await q.get()
                await ws.send_text(msg)
        except WebSocketDisconnect:
            pass
        finally:
            hub.unsubscribe(q)

    return app
