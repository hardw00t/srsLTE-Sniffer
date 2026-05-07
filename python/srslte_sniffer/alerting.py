"""Webhook alerting for rogue-eNB events.

POSTs JSON to a configured URL when a rule fires, with a per-rule cooldown
so a single noisy cell can't flood the channel.

Slack/Teams/PagerDuty all accept the same JSON-over-HTTPS shape, so this
keeps it generic. Format:

    {
      "rule": "unknown_plmn",
      "severity": "high",
      "cell_id": 42,
      "plmn": "525-99",
      "detail": "...",
      "ts_us": 1700000000000000,
      "source": "srslte-sniffer"
    }
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterable
from typing import Any

import httpx

from .rogue_detector import Anomaly


@dataclasses.dataclass
class WebhookConfig:
    url: str
    cooldown_s: float = 60.0
    timeout_s: float = 5.0
    extra_headers: dict[str, str] | None = None


class WebhookAlerter:
    """Fire-and-forget webhook poster with per-(rule, cell) deduplication."""

    def __init__(self, cfg: WebhookConfig, client: httpx.Client | None = None) -> None:
        self.cfg = cfg
        self._client = client or httpx.Client(timeout=cfg.timeout_s)
        self._last_sent: dict[tuple[str, int | None], float] = {}
        self.sent = 0
        self.suppressed = 0
        self.failed = 0

    def _key(self, a: Anomaly) -> tuple[str, int | None]:
        return (a.rule, a.cell_id)

    def _should_send(self, a: Anomaly, now: float) -> bool:
        last = self._last_sent.get(self._key(a))
        if last is None:
            return True
        return (now - last) >= self.cfg.cooldown_s

    def _payload(self, a: Anomaly, now_us: int) -> dict[str, Any]:
        d = dataclasses.asdict(a)
        d["ts_us"] = now_us
        d["source"] = "srslte-sniffer"
        return d

    def fire(self, anomaly: Anomaly) -> bool:
        """Send the anomaly. Returns True if posted, False if suppressed
        or the HTTP call failed."""
        now = time.time()
        if not self._should_send(anomaly, now):
            self.suppressed += 1
            return False
        try:
            r = self._client.post(
                self.cfg.url,
                json=self._payload(anomaly, int(now * 1e6)),
                headers=self.cfg.extra_headers or {},
            )
            r.raise_for_status()
            self._last_sent[self._key(anomaly)] = now
            self.sent += 1
            return True
        except Exception:
            self.failed += 1
            return False

    def fire_many(self, anomalies: Iterable[Anomaly]) -> int:
        return sum(1 for a in anomalies if self.fire(a))

    def stats(self) -> dict[str, int]:
        return {"sent": self.sent, "suppressed": self.suppressed,
                "failed": self.failed}

    def close(self) -> None:
        self._client.close()


def post_anomalies(
    anomalies: Iterable[Anomaly],
    url: str,
    *,
    cooldown_s: float = 60.0,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, int]:
    """One-shot helper for the CLI: post a batch of anomalies and return
    stats."""
    alerter = WebhookAlerter(
        WebhookConfig(
            url=url, cooldown_s=cooldown_s,
            extra_headers=extra_headers,
        )
    )
    try:
        for a in anomalies:
            alerter.fire(a)
        return alerter.stats()
    finally:
        alerter.close()
