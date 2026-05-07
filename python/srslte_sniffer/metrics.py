"""Prometheus metrics surface.

Exposes:

  srslte_pagings_total{kind}            — counter
  srslte_decode_failures_total          — counter
  srslte_pipeline_dropped_total         — counter (backpressure drops)
  srslte_pipeline_processed_total       — counter (decoded)
  srslte_anomaly_events_total{rule,severity}  — counter (rogue detector)
  srslte_decode_latency_seconds         — histogram

Wire it into a `StreamingPipeline` via `bind_pipeline()` and serve via
`make_metrics_app()`.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

from .rogue_detector import Anomaly
from .streaming import StreamEvent, StreamingPipeline


class Metrics:
    """Group of Prometheus metrics. One instance per process — pass it to
    pipelines and detectors that need to publish."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self.pagings = Counter(
            "srslte_pagings_total",
            "Total decoded paging records.",
            ["kind"],
            registry=self.registry,
        )
        self.decode_failures = Counter(
            "srslte_decode_failures_total",
            "Total PCCH/BCCH decode failures.",
            registry=self.registry,
        )
        self.dropped = Counter(
            "srslte_pipeline_dropped_total",
            "Records dropped due to streaming backpressure.",
            registry=self.registry,
        )
        self.processed = Counter(
            "srslte_pipeline_processed_total",
            "Records processed through the streaming pipeline.",
            registry=self.registry,
        )
        self.anomalies = Counter(
            "srslte_anomaly_events_total",
            "Rogue-eNB anomaly events.",
            ["rule", "severity"],
            registry=self.registry,
        )
        self.decode_latency = Histogram(
            "srslte_decode_latency_seconds",
            "Per-packet decode latency.",
            buckets=(1e-5, 5e-5, 1e-4, 5e-4, 1e-3, 5e-3, 1e-2, 5e-2, 1e-1),
            registry=self.registry,
        )

    # ----- pipeline integration -----

    def on_event(self, ev: StreamEvent) -> None:
        if not ev.decode_ok:
            self.decode_failures.inc()
            return
        for r in ev.records:
            self.pagings.labels(kind=r.kind).inc()

    def on_anomaly(self, a: Anomaly) -> None:
        self.anomalies.labels(rule=a.rule, severity=a.severity).inc()

    def bind_pipeline(self, pipeline: StreamingPipeline) -> None:
        """Attach as a subscriber and snapshot pipeline counters."""
        pipeline.subscribe(self.on_event)
        # The Counters .processed/.dropped are pulled from the pipeline at
        # scrape time via the helper below.
        self._pipeline = pipeline

    def snapshot(self) -> None:
        """Reconcile pipeline running totals into the cumulative counters.
        Called at scrape time before generate_latest() to keep
        processed/dropped accurate without per-event work."""
        if hasattr(self, "_pipeline"):
            inc_p = self._pipeline.processed - getattr(self, "_last_p", 0)
            inc_d = self._pipeline.dropped - getattr(self, "_last_d", 0)
            if inc_p > 0:
                self.processed.inc(inc_p)
            if inc_d > 0:
                self.dropped.inc(inc_d)
            self._last_p = self._pipeline.processed
            self._last_d = self._pipeline.dropped


def make_metrics_app(metrics: Metrics):
    """Tiny FastAPI app exposing /metrics. Mounted standalone or alongside
    the dashboard."""
    from fastapi import FastAPI
    from fastapi.responses import Response

    app = FastAPI(title="srsLTE-Sniffer metrics")

    @app.get("/metrics")
    def _metrics() -> Response:
        metrics.snapshot()
        return Response(
            content=generate_latest(metrics.registry),
            media_type=CONTENT_TYPE_LATEST,
        )

    @app.get("/")
    def _index() -> dict:
        return {"status": "ok", "metrics_endpoint": "/metrics"}

    return app
