"""PRACH ↔ paging correlation skeleton.

When the eNB pages a UE, that UE replies with a Random Access Preamble on
PRACH. By correlating paging events with subsequent PRACH preambles within
a short window, we can build a UE-attach timing histogram — useful for
detecting forced re-attach attacks (a rogue eNB symptom) and for
load-monitoring.

This module is a **skeleton** — it accepts already-extracted PRACH events
(produced by a hypothetical PHY-level capture path that is out of scope of
this branch) and runs the correlation. The realtime PRACH extractor is in
``src/pdsch_sniffer/`` territory and requires srsRAN_4G PRACH detector
hooks; that work is documented in ``docs/NR_REALTIME.md``.
"""

from __future__ import annotations

import dataclasses
from collections import Counter
from collections.abc import Iterable

from .tracker import TimedPaging


@dataclasses.dataclass
class PrachEvent:
    ts_us: int
    cell_id: int | None
    preamble_id: int  # 0..63
    timing_advance: int | None = None  # in TA units (16 Ts)


@dataclasses.dataclass
class CorrelatedAttach:
    paging: TimedPaging
    prach: PrachEvent
    delta_us: int

    @property
    def kind(self) -> str:
        return self.paging.record.kind


def correlate(
    pagings: Iterable[TimedPaging],
    prach_events: Iterable[PrachEvent],
    *,
    window_us: int = 80_000,  # ~80 ms typical paging→RA window
) -> list[CorrelatedAttach]:
    """Pair each paging with the closest subsequent PRACH on the same cell
    inside ``window_us``. PRACH events that fall in multiple windows are
    awarded to the nearest paging."""
    pagings = sorted(pagings, key=lambda p: p.ts_us)
    prach_events = sorted(prach_events, key=lambda e: e.ts_us)
    used: set[int] = set()
    out: list[CorrelatedAttach] = []
    pi = 0
    for ev in prach_events:
        # Advance pi to the first paging whose ts <= ev.ts and not too far back
        while (pi < len(pagings)
               and pagings[pi].ts_us < ev.ts_us - window_us):
            pi += 1
        # Find the candidate paging within the window on the same cell
        best_idx = None
        best_delta = window_us + 1
        for j in range(pi, len(pagings)):
            p = pagings[j]
            if p.ts_us > ev.ts_us:
                break
            if j in used:
                continue
            if p.cell_id is not None and ev.cell_id is not None \
                    and p.cell_id != ev.cell_id:
                continue
            delta = ev.ts_us - p.ts_us
            if 0 <= delta <= window_us and delta < best_delta:
                best_delta = delta
                best_idx = j
        if best_idx is not None:
            used.add(best_idx)
            out.append(CorrelatedAttach(
                paging=pagings[best_idx],
                prach=ev,
                delta_us=best_delta,
            ))
    return out


def attach_latency_histogram(
    correlated: Iterable[CorrelatedAttach],
    *,
    bin_ms: int = 5,
) -> dict[int, int]:
    """Bucket attach latency (ms) into ``bin_ms``-wide bins. Useful as a
    quick health check; rogue cells typically show a tighter distribution."""
    bins: Counter[int] = Counter()
    for c in correlated:
        ms = c.delta_us / 1000
        bin_idx = int(ms // bin_ms)
        bins[bin_idx * bin_ms] += 1
    return dict(sorted(bins.items()))
