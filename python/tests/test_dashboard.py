"""Dashboard FastAPI smoke test — uses TestClient, no live server."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from srslte_sniffer.dashboard import make_app
from srslte_sniffer.db import CaptureDB
from srslte_sniffer.decoder import PLMN, PagingRecord, SIB1


def _seed(db_path: Path) -> None:
    db = CaptureDB(db_path)
    try:
        db.insert_paging(
            PagingRecord(kind="imsi", cn_domain="ps", imsi="525058131997813"),
            ts_us=1_000_000, earfcn=1450, cell_id=1,
        )
        db.insert_paging(
            PagingRecord(kind="s-tmsi", cn_domain="ps",
                         mmec=22, m_tmsi=0xC445A820),
            ts_us=2_000_000, earfcn=1450, cell_id=1,
        )
        db.insert_cell(
            SIB1(plmns=[PLMN(mcc="525", mnc="05")],
                 tracking_area_code=2001, cell_id=1, si_periodicity=8),
            earfcn=1450, cell_id=1,
        )
    finally:
        db.close()


def test_index(tmp_path: Path):
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/")
    assert r.status_code == 200
    assert "srsLTE-Sniffer" in r.text
    assert "525058131997813" in r.text


def test_imsis_page(tmp_path: Path):
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/imsis")
    assert r.status_code == 200


def test_api_stats(tmp_path: Path):
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/stats")
    assert r.status_code == 200
    data = r.json()
    assert data["pagings"] == 2
    assert data["cells"] == 1


def test_api_recent(tmp_path: Path):
    db_path = tmp_path / "x.db"
    _seed(db_path)
    client = TestClient(make_app(str(db_path)))
    r = client.get("/api/recent?limit=10")
    assert r.status_code == 200
    rows = r.json()
    assert len(rows) == 2
