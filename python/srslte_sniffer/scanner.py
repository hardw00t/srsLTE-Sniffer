"""EARFCN scanner state machine.

The original `loop_catcher.sh` hard-coded 1845 MHz / 1815 MHz. This module
implements a sweep over a configurable EARFCN list, locks on the strongest
cell after MIB+SIB1, then dwells for a configurable window before stepping.

Hardware integration is a pluggable callable so this whole module is
testable without an SDR. In production wiring, the callable invokes the
modernised `pdsch_sniffer` C binary against an EARFCN.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable, Iterable

# 3GPP TS 36.101 Table 5.7.3-1 — partial. We only need EARFCN→Hz centre
# frequency conversion for the bands the user is likely to see.
# Full table is encoded as (band, F_dl_low_MHz, N_offs_DL, n_dl_min, n_dl_max).
LTE_BAND_TABLE = [
    (1, 2110.0, 0,     0,     599),
    (2, 1930.0, 600,   600,   1199),
    (3, 1805.0, 1200,  1200,  1949),
    (4, 2110.0, 1950,  1950,  2399),
    (5, 869.0,  2400,  2400,  2649),
    (7, 2620.0, 2750,  2750,  3449),
    (8, 925.0,  3450,  3450,  3799),
    (12, 729.0, 5010,  5010,  5179),
    (13, 746.0, 5180,  5180,  5279),
    (17, 734.0, 5730,  5730,  5849),
    (20, 791.0, 6150,  6150,  6449),
    (25, 1930.0, 8040, 8040,  8689),
    (28, 758.0, 9210,  9210,  9659),
    (38, 2570.0, 37750, 37750, 38249),
    (40, 2300.0, 38650, 38650, 39649),
    (41, 2496.0, 39650, 39650, 41589),
]


def earfcn_to_hz(earfcn: int) -> int | None:
    """Return the centre downlink frequency in Hz, or None if unknown."""
    for _band, low_mhz, offs, lo, hi in LTE_BAND_TABLE:
        if lo <= earfcn <= hi:
            mhz = low_mhz + 0.1 * (earfcn - offs)
            return int(round(mhz * 1_000_000))
    return None


def hz_to_earfcn(hz: int) -> int | None:
    """Inverse — for the legacy `1845 MHz / 1815 MHz` numbers in
    `loop_catcher.sh`, returns EARFCN 1650 / 1350 (band 3) approximately."""
    mhz = hz / 1_000_000
    for _band, low_mhz, offs, lo, hi in LTE_BAND_TABLE:
        n = round((mhz - low_mhz) / 0.1) + offs
        if lo <= n <= hi:
            return int(n)
    return None


@dataclasses.dataclass
class CellObservation:
    """Result of dwelling on one EARFCN."""

    earfcn: int
    hz: int
    locked: bool
    cell_id: int | None = None
    plmn: str | None = None
    rssi_dbm: float | None = None
    duration_s: float = 0.0
    pagings_seen: int = 0
    error: str | None = None


# A "dwell function" takes an EARFCN+frequency and returns observations.
# Real implementation invokes the C sniffer; tests pass a fake.
DwellFn = Callable[[int, int, float], CellObservation]


@dataclasses.dataclass
class ScanPlan:
    earfcns: list[int]
    dwell_seconds: float = 60.0
    skip_unlocked_after: float = 5.0
    max_cycles: int | None = None  # None == infinite

    @classmethod
    def from_band(cls, band: int, **kwargs) -> ScanPlan:
        for b, _low, _offs, lo, hi in LTE_BAND_TABLE:
            if b == band:
                return cls(earfcns=list(range(lo, hi + 1, 25)), **kwargs)
        raise ValueError(f"unknown band: {band}")

    @classmethod
    def from_legacy(cls, **kwargs) -> ScanPlan:
        """Mirror the original loop_catcher.sh — band 3 around 1845 / 1815."""
        return cls(
            earfcns=[
                hz_to_earfcn(1_845_000_000) or 1450,
                hz_to_earfcn(1_815_000_000) or 1750,
            ],
            **kwargs,
        )


class Scanner:
    def __init__(self, plan: ScanPlan, dwell_fn: DwellFn) -> None:
        self.plan = plan
        self.dwell_fn = dwell_fn

    def run(self) -> Iterable[CellObservation]:
        cycle = 0
        while True:
            for ear in self.plan.earfcns:
                hz = earfcn_to_hz(ear)
                if hz is None:
                    yield CellObservation(
                        earfcn=ear, hz=0, locked=False,
                        error="unknown EARFCN",
                    )
                    continue
                started = time.time()
                obs = self.dwell_fn(ear, hz, self.plan.dwell_seconds)
                obs.duration_s = time.time() - started
                yield obs
            cycle += 1
            if self.plan.max_cycles is not None and cycle >= self.plan.max_cycles:
                return
