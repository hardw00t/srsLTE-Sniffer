"""Multi-node aggregation: capture-node push + central hub receiver.

Architecture:

    [sniffer node] --(NDJSON over HTTPS)--> [hub]
    [sniffer node] --(NDJSON over HTTPS)--> [hub] --> SQLite

The push side is a thin coroutine that batches records and POSTs them
to a configurable URL with optional bearer-token auth. The hub side is a
FastAPI app that accepts those batches and writes them straight into the
existing CaptureDB.

NDJSON line format (one record per line):

    {"node_id": "sn1", "ts_us": ..., "kind": "paging",
     "radio_type": "4g",                          # 2g | 3g | 4g | 5g-nsa | 5g-sa
     "record": {"kind":"imsi"|"tmsi"|... , ...},  # generation-specific fields
     "earfcn": ..., "arfcn": ..., "cell_id": ...}

The wire format carries every WidePagingRecord field, so 2G/3G/5G
captures pushed via the hub round-trip without losing identifiers.
v2.2 hubs that only emitted 4G fields are forward-compatible: missing
fields default to None.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from collections.abc import Iterable
from typing import Any

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .db import CaptureDB
from .decoder_common import WidePagingRecord
from .streaming import StreamEvent

# ---- pusher ----------------------------------------------------------


@dataclasses.dataclass
class PushConfig:
    url: str  # e.g. https://hub.example/ingest
    node_id: str
    auth_token: str | None = None
    batch_size: int = 50
    flush_interval_s: float = 5.0
    timeout_s: float = 10.0


class PushClient:
    """Buffers events and POSTs them to the hub. Survives outages by
    keeping a bounded in-memory queue (older entries dropped on overflow)."""

    def __init__(self, cfg: PushConfig,
                 client: httpx.AsyncClient | None = None,
                 max_buffer: int = 5000) -> None:
        self.cfg = cfg
        self._client = client or httpx.AsyncClient(timeout=cfg.timeout_s)
        self._buffer: list[dict[str, Any]] = []
        self._max_buffer = max_buffer
        self._lock = asyncio.Lock()
        self._stop = asyncio.Event()
        self.posted = 0
        self.dropped = 0
        self.failures = 0

    def _serialize(self, ev: StreamEvent) -> list[dict[str, Any]]:
        """One JSON object per record. The pipeline today emits
        ``decoder.PagingRecord`` (4G shape) — those carry only the
        4G-specific identifiers. Cross-radio captures going through
        ``gsm_adapter`` write straight to the DB without traversing this
        path, so 4G shape is sufficient here. The wire format itself is
        wide so a future cross-radio streaming pipeline drop-in works."""
        out = []
        for r in ev.records:
            out.append({
                "node_id": self.cfg.node_id,
                "ts_us": ev.ts_us,
                "kind": "paging",
                "radio_type": "4g",
                "record": {
                    "kind": r.kind,
                    "imsi": r.imsi,
                    "mmec": r.mmec,
                    "m_tmsi": r.m_tmsi,
                    "cn_domain": r.cn_domain,
                },
            })
        return out

    @staticmethod
    def serialize_wide(
        wide: WidePagingRecord,
        *,
        node_id: str,
        ts_us: int,
        cell_id: int | None = None,
        earfcn: int | None = None,
        arfcn: int | None = None,
    ) -> dict[str, Any]:
        """Serialise a multi-radio WidePagingRecord into the wire shape.
        Used by adapters (gsm_adapter, future 5G/3G adapters) that bypass
        the StreamEvent path."""
        return {
            "node_id": node_id,
            "ts_us": ts_us,
            "kind": "paging",
            "radio_type": wide.radio_type,
            "earfcn": earfcn,
            "arfcn": arfcn,
            "cell_id": cell_id,
            "record": {
                "kind": wide.kind,
                "imsi": wide.imsi,
                "tmsi": wide.tmsi,
                "p_tmsi": wide.p_tmsi,
                "mmec": wide.mmec,
                "m_tmsi": wide.m_tmsi,
                "ng_5g_s_tmsi": wide.ng_5g_s_tmsi,
                "i_rnti": wide.i_rnti,
                "full_i_rnti": wide.full_i_rnti,
                "imei": wide.imei,
                "imeisv": wide.imeisv,
            },
        }

    async def on_event(self, ev: StreamEvent) -> None:
        if not ev.decode_ok or not ev.records:
            return
        items = self._serialize(ev)
        async with self._lock:
            for it in items:
                if len(self._buffer) >= self._max_buffer:
                    self._buffer.pop(0)  # drop oldest
                    self.dropped += 1
                self._buffer.append(it)

    async def _flush_once(self) -> int:
        async with self._lock:
            if not self._buffer:
                return 0
            batch = self._buffer[: self.cfg.batch_size]
            self._buffer = self._buffer[self.cfg.batch_size :]
        body = "\n".join(json.dumps(item) for item in batch)
        headers = {"content-type": "application/x-ndjson"}
        if self.cfg.auth_token:
            headers["authorization"] = f"Bearer {self.cfg.auth_token}"
        try:
            r = await self._client.post(self.cfg.url, content=body,
                                        headers=headers)
            r.raise_for_status()
            self.posted += len(batch)
            return len(batch)
        except Exception:
            self.failures += 1
            # Push failed — return the items to the front of the queue.
            async with self._lock:
                self._buffer = batch + self._buffer
            return 0

    async def run(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(),
                                       timeout=self.cfg.flush_interval_s)
            except asyncio.TimeoutError:
                pass
            await self._flush_once()
        # Final drain on stop.
        await self._flush_once()

    def stop(self) -> None:
        self._stop.set()

    async def aclose(self) -> None:
        await self._client.aclose()

    def stats(self) -> dict[str, int]:
        return {"posted": self.posted, "dropped": self.dropped,
                "failures": self.failures, "buffered": len(self._buffer)}


# ---- hub --------------------------------------------------------------


def make_hub_app(db_path: str, *, auth_token: str | None = None) -> FastAPI:
    """Build the receiving side. Accepts NDJSON batches at /ingest and
    writes them into the shared CaptureDB."""
    app = FastAPI(title="srsLTE-Sniffer hub", version="2.2.0")

    def _check_auth(request: Request) -> None:
        if not auth_token:
            return
        h = request.headers.get("authorization", "")
        if h != f"Bearer {auth_token}":
            raise HTTPException(status_code=401, detail="bad token")

    @app.post("/ingest")
    async def ingest(request: Request,
                     _: None = Depends(_check_auth)) -> JSONResponse:
        body = (await request.body()).decode("utf-8", errors="replace")
        n_inserted = 0
        n_skipped = 0
        db = CaptureDB(db_path)
        try:
            for raw in body.splitlines():
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    item = json.loads(raw)
                except json.JSONDecodeError:
                    n_skipped += 1
                    continue
                if item.get("kind") != "paging":
                    n_skipped += 1
                    continue
                rec_data = item.get("record") or {}
                # Construct a WidePagingRecord — covers every generation.
                # Old (v2.2) clients that only sent 4G fields fill the
                # rest with None which insert_wide_paging accepts.
                wide = WidePagingRecord(
                    radio_type=item.get("radio_type", "4g"),
                    kind=rec_data.get("kind", "unknown"),
                    imsi=rec_data.get("imsi"),
                    tmsi=rec_data.get("tmsi"),
                    p_tmsi=rec_data.get("p_tmsi"),
                    mmec=rec_data.get("mmec"),
                    m_tmsi=rec_data.get("m_tmsi"),
                    ng_5g_s_tmsi=rec_data.get("ng_5g_s_tmsi"),
                    i_rnti=rec_data.get("i_rnti"),
                    full_i_rnti=rec_data.get("full_i_rnti"),
                    imei=rec_data.get("imei"),
                    imeisv=rec_data.get("imeisv"),
                )
                db.insert_wide_paging(
                    wide,
                    ts_us=item.get("ts_us"),
                    earfcn=item.get("earfcn"),
                    arfcn=item.get("arfcn"),
                    cell_id=item.get("cell_id"),
                )
                n_inserted += 1
        finally:
            db.close()
        return JSONResponse(
            {"inserted": n_inserted, "skipped": n_skipped},
            status_code=200,
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


# ---- cross-node correlation ------------------------------------------


def correlate_subscriber_movement(db: CaptureDB,
                                  *, window_s: int = 300) -> dict[str, list[int]]:
    """Find IMSIs/M-TMSIs paged on >1 cell within ``window_s`` — a strong
    indicator of UE mobility. Returns identifier → list of cell IDs."""
    out: dict[str, set[int]] = {}
    rows = db._conn.execute(
        "SELECT ts, kind, imsi, mmec, m_tmsi, cell_id FROM pagings "
        "WHERE cell_id IS NOT NULL "
        "ORDER BY ts ASC"
    ).fetchall()
    last_seen: dict[str, tuple[int, int]] = {}
    for ts, kind, imsi, mmec, m_tmsi, cell_id in rows:
        if kind == "imsi" and imsi:
            key = f"imsi:{imsi}"
        elif kind == "s-tmsi" and m_tmsi is not None:
            key = f"stmsi:{mmec}:{m_tmsi}"
        else:
            continue
        prev = last_seen.get(key)
        if prev:
            prev_ts, prev_cell = prev
            if (
                prev_cell != cell_id
                and (ts - prev_ts) <= window_s * 1_000_000
            ):
                out.setdefault(key, set()).update({prev_cell, cell_id})
        last_seen[key] = (ts, cell_id)
    return {k: sorted(v) for k, v in out.items()}


def push_records_sync(records: Iterable[dict],
                      url: str,
                      *,
                      auth_token: str | None = None,
                      timeout_s: float = 10.0) -> dict[str, int]:
    """Blocking helper for tests + simple scripts."""
    headers = {"content-type": "application/x-ndjson"}
    if auth_token:
        headers["authorization"] = f"Bearer {auth_token}"
    body = "\n".join(json.dumps(r) for r in records)
    with httpx.Client(timeout=timeout_s) as client:
        r = client.post(url, content=body, headers=headers)
        r.raise_for_status()
        return r.json()
