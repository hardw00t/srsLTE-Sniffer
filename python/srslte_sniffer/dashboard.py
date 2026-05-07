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
) -> FastAPI:
    app = FastAPI(title="srsLTE-Sniffer dashboard", version="2.0.0")
    hub = _Hub()
    if pipeline is not None:
        pipeline.subscribe(hub.publish)

    def _db() -> CaptureDB:
        return CaptureDB(db_path)

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
