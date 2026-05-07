"""Live dashboard — FastAPI + HTMX. No React, no build step.

Run:  srslte-sniffer dashboard --db captures.db --port 8000

Renders:
    /            — overview (counts, recent pagings)
    /cells       — observed cells (SIB1)
    /imsis       — IMSI leaderboard with first/last seen
    /api/stats   — JSON for HTMX polling
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .db import CaptureDB

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


def make_app(db_path: str) -> FastAPI:
    app = FastAPI(title="srsLTE-Sniffer dashboard", version="2.0.0")

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
            return JSONResponse(db.stats())
        finally:
            db.close()

    @app.get("/api/recent")
    def recent_json(limit: int = 50):
        db = _db()
        try:
            return JSONResponse(db.recent_pagings(limit))
        finally:
            db.close()

    return app
