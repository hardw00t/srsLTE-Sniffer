"""Hub receiver + push client tests."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.hub import (
    correlate_subscriber_movement,
    make_hub_app,
    push_records_sync,
)


def test_ingest_writes_records(tmp_path):
    db_path = tmp_path / "hub.db"
    app = make_hub_app(str(db_path))
    client = TestClient(app)

    body = "\n".join([
        json.dumps({
            "node_id": "sn1", "ts_us": 1_000_000, "kind": "paging",
            "record": {"kind": "imsi", "imsi": "525058131997813",
                       "cn_domain": "ps"},
            "earfcn": 1450, "cell_id": 42,
        }),
        json.dumps({
            "node_id": "sn1", "ts_us": 2_000_000, "kind": "paging",
            "record": {"kind": "s-tmsi", "mmec": 22, "m_tmsi": 0xCAFE,
                       "cn_domain": "ps"},
            "earfcn": 1450, "cell_id": 42,
        }),
    ])
    r = client.post("/ingest", content=body,
                    headers={"content-type": "application/x-ndjson"})
    assert r.status_code == 200
    assert r.json() == {"inserted": 2, "skipped": 0}

    db = CaptureDB(db_path)
    try:
        assert db.count("pagings") == 2
        rows = db._conn.execute(
            "SELECT kind, imsi, m_tmsi FROM pagings ORDER BY id"
        ).fetchall()
        assert rows[0] == ("imsi", "525058131997813", None)
        assert rows[1] == ("s-tmsi", None, 0xCAFE)
    finally:
        db.close()


def test_ingest_skips_garbage(tmp_path):
    db_path = tmp_path / "hub.db"
    app = make_hub_app(str(db_path))
    client = TestClient(app)
    body = "not json\n" + json.dumps({"kind": "junk"}) + "\n"
    r = client.post("/ingest", content=body)
    assert r.status_code == 200
    assert r.json() == {"inserted": 0, "skipped": 2}


def test_ingest_auth_required(tmp_path):
    db_path = tmp_path / "hub.db"
    app = make_hub_app(str(db_path), auth_token="s3cret")
    client = TestClient(app)
    r = client.post("/ingest", content="")
    assert r.status_code == 401
    r = client.post("/ingest", content="",
                    headers={"authorization": "Bearer s3cret"})
    assert r.status_code == 200


def test_health_endpoint(tmp_path):
    app = make_hub_app(str(tmp_path / "hub.db"))
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_correlate_subscriber_movement(tmp_path):
    db_path = tmp_path / "hub.db"
    db = CaptureDB(db_path)
    try:
        # IMSI seen on cell 1 then cell 2 within 30s → mobility
        db.insert_paging(
            PagingRecord(kind="imsi", cn_domain="ps", imsi="525050000000001"),
            ts_us=10_000_000, cell_id=1,
        )
        db.insert_paging(
            PagingRecord(kind="imsi", cn_domain="ps", imsi="525050000000001"),
            ts_us=20_000_000, cell_id=2,
        )
        # Different IMSI only on one cell — no mobility entry
        db.insert_paging(
            PagingRecord(kind="imsi", cn_domain="ps", imsi="525050000000002"),
            ts_us=30_000_000, cell_id=2,
        )
        m = correlate_subscriber_movement(db, window_s=60)
        assert "imsi:525050000000001" in m
        assert m["imsi:525050000000001"] == [1, 2]
        assert "imsi:525050000000002" not in m
    finally:
        db.close()


def test_push_records_sync_via_mock_transport(tmp_path):
    """Swap httpx transport via httpx.MockTransport so we can verify the
    request shape without booting a server."""
    import httpx

    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["headers"] = dict(request.headers)
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"inserted": 1, "skipped": 0})

    transport = httpx.MockTransport(handler)
    # Patch httpx.Client to inject our transport.
    real = httpx.Client
    httpx.Client = lambda *a, **kw: real(transport=transport, **kw)
    try:
        res = push_records_sync(
            [{
                "node_id": "n", "ts_us": 1, "kind": "paging",
                "record": {"kind": "s-tmsi", "mmec": 22, "m_tmsi": 1},
            }],
            url="http://hub/ingest",
            auth_token="t",
        )
    finally:
        httpx.Client = real

    assert res == {"inserted": 1, "skipped": 0}
    assert seen["headers"]["authorization"] == "Bearer t"
    assert seen["headers"]["content-type"] == "application/x-ndjson"
    assert "525" not in seen["body"] and "s-tmsi" in seen["body"]


@pytest.mark.asyncio_or_thread
def test_push_client_buffers_and_drains(tmp_path):
    """Smoke test for PushClient batching logic (offline)."""
    import asyncio
    import httpx

    from srslte_sniffer.hub import PushClient, PushConfig
    from srslte_sniffer.streaming import StreamEvent

    db_path = tmp_path / "hub.db"
    app = make_hub_app(str(db_path))
    transport = httpx.ASGITransport(app=app)

    async def _run():
        async with httpx.AsyncClient(transport=transport,
                                     base_url="http://hub") as client:
            cfg = PushConfig(
                url="http://hub/ingest", node_id="sn1",
                batch_size=10, flush_interval_s=0.05,
            )
            pc = PushClient(cfg, client=client)

            # Inject 25 events
            for i in range(25):
                ev = StreamEvent(
                    kind=1, ts_us=i, raw=b"",
                    records=[PagingRecord(
                        kind="s-tmsi", cn_domain="ps",
                        mmec=22, m_tmsi=i,
                    )],
                    decode_ok=True,
                )
                await pc.on_event(ev)

            task = asyncio.create_task(pc.run())
            # Let three flush cycles run.
            await asyncio.sleep(0.2)
            pc.stop()
            await task
            return pc.stats()

    stats = asyncio.run(_run())
    assert stats["posted"] == 25
    assert stats["failures"] == 0

    db = CaptureDB(db_path)
    try:
        assert db.count("pagings") == 25
    finally:
        db.close()
