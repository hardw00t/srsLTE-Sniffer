"""Tests for the new dashboard surface: time-series, map, anomalies API,
auth gate, and the geo cache integration."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from srslte_sniffer.dashboard import make_app
from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PLMN, PagingRecord, SIB1
from srslte_sniffer.geo import GeoCache


def _seed(db_path: Path) -> None:
    db = CaptureDB(db_path)
    try:
        for ts in range(0, 600_000_000, 60_000_000):  # ten 1-min buckets
            db.insert_paging(
                PagingRecord(kind="s-tmsi", cn_domain="ps",
                             mmec=22, m_tmsi=ts),
                ts_us=ts, cell_id=42,
            )
        db.insert_cell(
            SIB1(plmns=[PLMN(mcc="525", mnc="05")],
                 tracking_area_code=2001, cell_id=42, si_periodicity=8),
            cell_id=42,
        )
    finally:
        db.close()


def test_timeseries_buckets_by_minute(tmp_path):
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/timeseries?bucket_seconds=60")
    assert r.status_code == 200
    data = r.json()
    assert data["bucket_seconds"] == 60
    assert len(data["series"]) == 10


def test_anomalies_endpoint(tmp_path):
    """No anomalies expected on the seeded baseline."""
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/anomalies?allowed_plmns=525-05")
    assert r.status_code == 200
    assert r.json() == []


def test_cells_map_renders_with_geo(tmp_path):
    db_path = tmp_path / "x.db"
    geo_path = tmp_path / "geo.db"
    _seed(db_path)

    geo = GeoCache(geo_path)
    try:
        # A single matching geo row.
        geo._conn.execute(
            "INSERT INTO cell_geo VALUES (525, 5, 2001, 42, "
            "103.8198, 1.3521, 1000)"
        )
    finally:
        geo.close()

    client = TestClient(make_app(str(db_path), geo_db_path=str(geo_path)))
    r = client.get("/cells/map")
    assert r.status_code == 200
    assert "Leaflet" in r.text or "leaflet" in r.text
    assert "103.8198" in r.text


def test_auth_token_required(tmp_path):
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path), auth_token="s3cret"))

    r = client.get("/")
    assert r.status_code == 401

    r = client.get("/", headers={"x-auth-token": "wrong"})
    assert r.status_code == 401

    r = client.get("/", headers={"x-auth-token": "s3cret"})
    assert r.status_code == 200


def test_auth_open_when_no_token(tmp_path):
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path), auth_token=None))
    assert client.get("/").status_code == 200
