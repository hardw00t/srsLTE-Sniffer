"""Prometheus exporter tests."""

from __future__ import annotations

from fastapi.testclient import TestClient

from srslte_sniffer.decoder import PagingRecord
from srslte_sniffer.metrics import Metrics, make_metrics_app
from srslte_sniffer.rogue_detector import Anomaly
from srslte_sniffer.streaming import StreamEvent


def test_counters_increment_on_event():
    m = Metrics()
    ev = StreamEvent(
        kind=1, ts_us=0, raw=b"",
        records=[PagingRecord(kind="imsi", cn_domain="ps",
                              imsi="525058131997813")],
        decode_ok=True,
    )
    m.on_event(ev)
    m.on_event(ev)
    text = _scrape(m)
    assert (
        'srslte_pagings_total{kind="imsi",radio_type="4g"} 2.0' in text
        or 'srslte_pagings_total{radio_type="4g",kind="imsi"} 2.0' in text
    )


def test_decode_failure_counts():
    m = Metrics()
    ev = StreamEvent(kind=1, ts_us=0, raw=b"", records=[],
                     decode_ok=False, error="bitlen overflow")
    m.on_event(ev)
    text = _scrape(m)
    assert "srslte_decode_failures_total 1.0" in text


def test_anomaly_counter_labels():
    m = Metrics()
    m.on_anomaly(Anomaly(rule="unknown_plmn", severity="high",
                         cell_id=1, plmn="999-99", detail=""))
    text = _scrape(m)
    assert (
        'srslte_anomaly_events_total{rule="unknown_plmn",severity="high"} 1.0'
        in text
    )


def test_metrics_endpoint_serves_text():
    m = Metrics()
    m.on_event(StreamEvent(
        kind=1, ts_us=0, raw=b"",
        records=[PagingRecord(kind="s-tmsi", cn_domain="ps",
                              mmec=22, m_tmsi=1)],
        decode_ok=True,
    ))
    client = TestClient(make_metrics_app(m))
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert 'kind="s-tmsi"' in r.text and 'radio_type="4g"' in r.text


def _scrape(m: Metrics) -> str:
    from prometheus_client import generate_latest
    return generate_latest(m.registry).decode()
