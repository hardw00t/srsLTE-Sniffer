"""Rogue-eNB anomaly detector.

The flip side of an IMSI catcher: detect *other* people's IMSI catchers by
spotting cells whose SIB1 or paging behaviour is anomalous compared to a
trusted baseline.

Rules implemented (each returns one or more `Anomaly` records):

1. **Unknown PLMN** — cell announces a PLMN that's not on the allow-list.
2. **PLMN mismatch with neighbours** — a cell on the same TAC announces a
   different PLMN than the rest of the area.
3. **Excessive S-TMSI churn** — a single cell hands out many S-TMSIs per
   IMSI in a short window; legitimate cells churn rarely.
4. **Suspicious SI periodicity** — SIB scheduling deviating from the
   neighbouring cells.
5. **Forced reattach** — a high rate of IMSI paging (vs S-TMSI paging) on
   a single cell. Real LTE networks page by IMSI as a fallback only.

Each rule is a pure function over the captured DB so they can run as a
post-processing job *or* as a streaming alarm via the dashboard.
"""

from __future__ import annotations

import dataclasses
from collections import Counter, defaultdict
from collections.abc import Iterable

from .tracker import TimedPaging, churn_per_cell


@dataclasses.dataclass
class Anomaly:
    rule: str
    severity: str  # "low" | "medium" | "high"
    cell_id: int | None
    plmn: str | None
    detail: str


@dataclasses.dataclass
class CellSnapshot:
    cell_id: int
    plmn: str | None
    tac: int | None
    si_periodicity: int | None
    paging_imsi_count: int = 0
    paging_stmsi_count: int = 0


def detect_unknown_plmn(
    cells: Iterable[CellSnapshot],
    allowed_plmns: set[str],
) -> list[Anomaly]:
    out = []
    for c in cells:
        if c.plmn and c.plmn not in allowed_plmns:
            out.append(
                Anomaly(
                    rule="unknown_plmn",
                    severity="high",
                    cell_id=c.cell_id,
                    plmn=c.plmn,
                    detail=f"PLMN {c.plmn} not in allow-list",
                )
            )
    return out


def detect_plmn_mismatch_in_tac(cells: Iterable[CellSnapshot]) -> list[Anomaly]:
    """Within a TAC, all cells should advertise (one of) the same PLMNs."""
    by_tac: dict[int, list[CellSnapshot]] = defaultdict(list)
    for c in cells:
        if c.tac is not None:
            by_tac[c.tac].append(c)
    out = []
    for tac, group in by_tac.items():
        plmns = Counter(c.plmn for c in group if c.plmn)
        if len(plmns) <= 1:
            continue
        # The minority PLMN is suspect.
        majority = plmns.most_common(1)[0][0]
        for c in group:
            if c.plmn and c.plmn != majority:
                out.append(
                    Anomaly(
                        rule="plmn_mismatch_in_tac",
                        severity="high",
                        cell_id=c.cell_id,
                        plmn=c.plmn,
                        detail=(
                            f"TAC {tac}: cell announces {c.plmn} but "
                            f"majority is {majority}"
                        ),
                    )
                )
    return out


def detect_excessive_stmsi_churn(
    timeline: Iterable[TimedPaging],
    *,
    threshold: int = 50,
) -> list[Anomaly]:
    churn = churn_per_cell(timeline)
    out = []
    for cell_id, n in churn.items():
        if n >= threshold:
            out.append(
                Anomaly(
                    rule="excessive_stmsi_churn",
                    severity="medium" if n < threshold * 2 else "high",
                    cell_id=cell_id,
                    plmn=None,
                    detail=f"{n} distinct S-TMSIs on cell {cell_id}",
                )
            )
    return out


def detect_imsi_paging_rate(cells: Iterable[CellSnapshot]) -> list[Anomaly]:
    """High imsi/(imsi+stmsi) ratio is a strong rogue-eNB signal — real
    networks fall back to IMSI paging only rarely."""
    out = []
    for c in cells:
        total = c.paging_imsi_count + c.paging_stmsi_count
        if total < 20:
            continue
        ratio = c.paging_imsi_count / total
        if ratio > 0.05:  # >5% IMSI paging is suspicious
            out.append(
                Anomaly(
                    rule="excessive_imsi_paging",
                    severity="high" if ratio > 0.2 else "medium",
                    cell_id=c.cell_id,
                    plmn=c.plmn,
                    detail=(
                        f"IMSI paging ratio {ratio:.0%} ({c.paging_imsi_count}"
                        f"/{total}) — well above 1–2% baseline"
                    ),
                )
            )
    return out


def detect_si_periodicity_outlier(
    cells: Iterable[CellSnapshot],
) -> list[Anomaly]:
    cells = list(cells)
    periods = [c.si_periodicity for c in cells if c.si_periodicity is not None]
    if len(periods) < 4:
        return []
    counts = Counter(periods)
    common = counts.most_common(1)[0][0]
    out = []
    for c in cells:
        if c.si_periodicity is None:
            continue
        if c.si_periodicity != common:
            out.append(
                Anomaly(
                    rule="si_periodicity_outlier",
                    severity="low",
                    cell_id=c.cell_id,
                    plmn=c.plmn,
                    detail=(
                        f"si-Periodicity rf{c.si_periodicity} differs from "
                        f"area majority rf{common}"
                    ),
                )
            )
    return out


def run_all(
    cells: Iterable[CellSnapshot],
    timeline: Iterable[TimedPaging],
    *,
    allowed_plmns: set[str] | None = None,
    churn_threshold: int = 50,
) -> list[Anomaly]:
    cells = list(cells)
    timeline = list(timeline)
    out: list[Anomaly] = []
    if allowed_plmns:
        out.extend(detect_unknown_plmn(cells, allowed_plmns))
    out.extend(detect_plmn_mismatch_in_tac(cells))
    out.extend(detect_excessive_stmsi_churn(timeline, threshold=churn_threshold))
    out.extend(detect_imsi_paging_rate(cells))
    out.extend(detect_si_periodicity_outlier(cells))
    return out
