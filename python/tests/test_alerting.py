"""Webhook alerter tests — uses an in-process httpx mock transport."""

from __future__ import annotations

import httpx
import pytest

from srslte_sniffer.alerting import WebhookAlerter, WebhookConfig
from srslte_sniffer.rogue_detector import Anomaly


def _alerter(handler) -> WebhookAlerter:
    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport)
    return WebhookAlerter(WebhookConfig(url="http://x/hook", cooldown_s=60.0),
                          client=client)


def test_fires_first_event():
    posted: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        import json
        posted.append(json.loads(request.content))
        return httpx.Response(200)

    a = _alerter(handler)
    ok = a.fire(Anomaly(rule="r", severity="high", cell_id=1,
                        plmn="525-99", detail="x"))
    assert ok
    assert len(posted) == 1
    assert posted[0]["rule"] == "r"
    assert posted[0]["severity"] == "high"
    assert posted[0]["source"] == "srslte-sniffer"


def test_cooldown_dedups():
    n = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal n
        n += 1
        return httpx.Response(200)

    a = _alerter(handler)
    anom = Anomaly(rule="r", severity="high", cell_id=1, plmn="x", detail="")
    a.fire(anom)
    a.fire(anom)  # within cooldown — must not POST
    assert n == 1
    assert a.suppressed == 1


def test_different_cells_not_deduped():
    posts = 0

    def handler(_):
        nonlocal posts
        posts += 1
        return httpx.Response(200)

    a = _alerter(handler)
    a.fire(Anomaly(rule="r", severity="h", cell_id=1, plmn="", detail=""))
    a.fire(Anomaly(rule="r", severity="h", cell_id=2, plmn="", detail=""))
    assert posts == 2


def test_handles_500_gracefully():
    def handler(_):
        return httpx.Response(500, content=b"oops")

    a = _alerter(handler)
    ok = a.fire(Anomaly(rule="r", severity="h", cell_id=1, plmn="",
                        detail=""))
    assert ok is False
    assert a.failed == 1


def test_post_anomalies_helper():
    from srslte_sniffer.alerting import post_anomalies

    n = 0

    def handler(_):
        nonlocal n
        n += 1
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    # The helper builds its own client; monkeypatch httpx.Client to use
    # our transport.
    real_client = httpx.Client
    httpx.Client = lambda *a, **kw: real_client(transport=transport, **kw)
    try:
        stats = post_anomalies(
            [Anomaly(rule="r", severity="h", cell_id=i, plmn="",
                     detail="") for i in range(3)],
            url="http://x/hook",
        )
    finally:
        httpx.Client = real_client
    assert stats["sent"] == 3
    assert n == 3
