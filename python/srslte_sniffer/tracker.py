"""TMSI-reassignment correlation.

When the network reassigns an S-TMSI for a subscriber, two records appear
close together in time and the same paging window — one carrying the IMSI,
one carrying the new S-TMSI. By windowing on time + cell, we can
*correlate* the two and follow a subscriber even when later pages only
carry the rotating S-TMSI.

This is the analyzer flavour of reference [4] in the original README:
"Sniff and Capture pg 57-61".

Defensive framing: this is also useful for detecting *unusual reassignment
churn* — a rogue eNB will typically force more frequent S-TMSI churn than
a legitimate one.
"""

from __future__ import annotations

import dataclasses
from collections import defaultdict
from collections.abc import Iterable

from .decoder import PagingRecord


@dataclasses.dataclass
class TimedPaging:
    record: PagingRecord
    ts_us: int
    earfcn: int | None = None
    cell_id: int | None = None


@dataclasses.dataclass
class TmsiReassignment:
    imsi: str
    old_mmec: int | None
    old_m_tmsi: int | None
    new_mmec: int
    new_m_tmsi: int
    ts_us: int
    confidence: float  # 0..1
    note: str = ""


def correlate(
    timeline: Iterable[TimedPaging],
    *,
    window_us: int = 200_000,  # 200 ms — typical paging window pair
) -> list[TmsiReassignment]:
    """Look for IMSI/S-TMSI pairs that appear within `window_us` of each
    other on the same cell, in either order.

    Heuristic — with passive captures we can't tie identities together with
    certainty, so we attach a confidence score:
        - 0.9 if exactly one IMSI and one S-TMSI co-occur in the window
        - 0.5 if multiple S-TMSIs co-occur with the IMSI
        - <0.5 if the cell has high paging volume in the window
    """
    events = sorted(timeline, key=lambda e: e.ts_us)
    out: list[TmsiReassignment] = []
    # Sliding window by index.
    n = len(events)
    for i, ev in enumerate(events):
        if ev.record.kind != "imsi" or not ev.record.imsi:
            continue
        # Sweep forward and backward within the window.
        nearby_stmsi: list[TimedPaging] = []
        nearby_imsi: list[TimedPaging] = []
        j = i - 1
        while j >= 0 and ev.ts_us - events[j].ts_us <= window_us:
            if events[j].cell_id == ev.cell_id:
                if events[j].record.kind == "s-tmsi":
                    nearby_stmsi.append(events[j])
                elif events[j].record.kind == "imsi":
                    nearby_imsi.append(events[j])
            j -= 1
        j = i + 1
        while j < n and events[j].ts_us - ev.ts_us <= window_us:
            if events[j].cell_id == ev.cell_id:
                if events[j].record.kind == "s-tmsi":
                    nearby_stmsi.append(events[j])
                elif events[j].record.kind == "imsi":
                    nearby_imsi.append(events[j])
            j += 1
        if not nearby_stmsi:
            continue

        # Score
        if len(nearby_stmsi) == 1 and not nearby_imsi:
            confidence = 0.9
            note = "single S-TMSI co-occurrence"
        elif len(nearby_stmsi) <= 3 and len(nearby_imsi) <= 1:
            confidence = 0.5
            note = "few S-TMSIs co-occurrence"
        else:
            confidence = max(0.05, 0.5 / (len(nearby_stmsi) + len(nearby_imsi)))
            note = f"high churn (S-TMSIs={len(nearby_stmsi)})"

        for st in nearby_stmsi:
            out.append(
                TmsiReassignment(
                    imsi=ev.record.imsi,
                    old_mmec=None,
                    old_m_tmsi=None,
                    new_mmec=st.record.mmec or 0,
                    new_m_tmsi=st.record.m_tmsi or 0,
                    ts_us=ev.ts_us,
                    confidence=confidence,
                    note=note,
                )
            )
    return out


@dataclasses.dataclass
class IdentityTrack:
    """Aggregated track for one subscriber across a session."""

    imsi: str
    seen_stmsis: set[tuple[int, int]] = dataclasses.field(default_factory=set)
    cells: set[int] = dataclasses.field(default_factory=set)
    first_ts: int = 0
    last_ts: int = 0
    pages: int = 0


def build_tracks(
    timeline: Iterable[TimedPaging],
    *,
    window_us: int = 200_000,
) -> list[IdentityTrack]:
    """Group correlated reassignments into per-IMSI tracks."""
    timeline = list(timeline)
    reassignments = correlate(timeline, window_us=window_us)
    tracks: dict[str, IdentityTrack] = {}
    for ev in timeline:
        if ev.record.kind == "imsi" and ev.record.imsi:
            t = tracks.setdefault(ev.record.imsi, IdentityTrack(imsi=ev.record.imsi))
            t.pages += 1
            t.first_ts = ev.ts_us if t.first_ts == 0 else min(t.first_ts, ev.ts_us)
            t.last_ts = max(t.last_ts, ev.ts_us)
            if ev.cell_id is not None:
                t.cells.add(ev.cell_id)
    for r in reassignments:
        if r.confidence < 0.5:
            continue
        t = tracks.setdefault(r.imsi, IdentityTrack(imsi=r.imsi))
        t.seen_stmsis.add((r.new_mmec, r.new_m_tmsi))
    return list(tracks.values())


def churn_per_cell(timeline: Iterable[TimedPaging]) -> dict[int, int]:
    """Count distinct S-TMSIs per cell — input for the rogue-eNB detector."""
    by_cell: dict[int, set[tuple[int, int]]] = defaultdict(set)
    for ev in timeline:
        if ev.record.kind == "s-tmsi" and ev.cell_id is not None:
            by_cell[ev.cell_id].add(
                (ev.record.mmec or 0, ev.record.m_tmsi or 0)
            )
    return {cell: len(s) for cell, s in by_cell.items()}
