"""Synthetic anomaly generator for the rogue-eNB rules.

Produces journals + DB seeds that simulate specific attack patterns. The
intent is to give the rogue-eNB rules a known-positive test corpus so we
catch regressions when rules drift.

Each `Pattern` is a tiny dataclass describing one scenario; the generator
emits the corresponding records. Tests in
`python/tests/test_synthesize.py` assert that each pattern triggers the
expected rule and *only* the expected rule, with the demo capture mixed
in as background noise.
"""

from __future__ import annotations

import dataclasses
import secrets
import time
from collections.abc import Iterable

from .db import CaptureDB
from .decoder import PLMN, SIB1, PagingRecord


@dataclasses.dataclass
class CellSpec:
    cell_id: int
    plmn: str  # "MCC-MNC"
    tac: int
    si_periodicity: int = 8


@dataclasses.dataclass
class PagingSpec:
    cell_id: int
    kind: str  # "imsi" | "s-tmsi"
    imsi: str | None = None
    mmec: int | None = None
    m_tmsi: int | None = None
    ts_us: int | None = None  # absolute; if None, generator assigns


# ---- patterns -----------------------------------------------------------


@dataclasses.dataclass
class Pattern:
    """One named attack scenario. The fields define what to emit."""

    name: str
    cells: list[CellSpec]
    pagings: list[PagingSpec]

    def expected_rules(self) -> set[str]:
        """The rule names this pattern should trigger when run through
        rogue_detector.run_all (with no allow-list).

        Override in subclasses or inspect via the helper functions
        below."""
        return set()


def pattern_unknown_plmn(allowed: set[str] | None = None) -> Pattern:
    """A cell announcing a PLMN not on the allow-list."""
    return Pattern(
        name="unknown_plmn",
        cells=[CellSpec(cell_id=999, plmn="999-99", tac=4242)],
        pagings=[PagingSpec(cell_id=999, kind="s-tmsi",
                            mmec=22, m_tmsi=0xDEADBEEF)],
    )


def pattern_plmn_mismatch_in_tac() -> Pattern:
    """One TAC, four cells — three on the same PLMN, one rogue."""
    cells = [
        CellSpec(cell_id=1, plmn="525-05", tac=2001),
        CellSpec(cell_id=2, plmn="525-05", tac=2001),
        CellSpec(cell_id=3, plmn="525-05", tac=2001),
        CellSpec(cell_id=4, plmn="525-99", tac=2001),  # rogue
    ]
    pagings = []
    for c in cells:
        pagings.append(PagingSpec(cell_id=c.cell_id, kind="s-tmsi",
                                   mmec=22, m_tmsi=c.cell_id * 1000))
    return Pattern(name="plmn_mismatch_in_tac", cells=cells, pagings=pagings)


def pattern_excessive_stmsi_churn(threshold: int = 50) -> Pattern:
    """One cell, many distinct S-TMSIs in a short window."""
    cell = CellSpec(cell_id=77, plmn="525-05", tac=2001)
    pagings = [
        PagingSpec(cell_id=77, kind="s-tmsi", mmec=22, m_tmsi=i)
        for i in range(threshold + 10)
    ]
    return Pattern(name="excessive_stmsi_churn",
                   cells=[cell], pagings=pagings)


def pattern_imsi_paging_storm() -> Pattern:
    """A cell pages by IMSI at well above the natural ~1–2% rate.

    Real LTE networks rarely page by IMSI (only on TMSI lookup miss);
    a flood is one of the strongest rogue-eNB signals.
    """
    cell = CellSpec(cell_id=88, plmn="525-05", tac=2001)
    pagings = []
    for i in range(40):
        pagings.append(PagingSpec(
            cell_id=88, kind="imsi",
            imsi=f"525050000{i:06d}",
        ))
    for i in range(60):
        pagings.append(PagingSpec(
            cell_id=88, kind="s-tmsi",
            mmec=22, m_tmsi=i,
        ))
    return Pattern(name="imsi_paging_storm",
                   cells=[cell], pagings=pagings)


def pattern_si_periodicity_outlier() -> Pattern:
    """An area where one cell broadcasts on an unusual SI period."""
    cells = [
        CellSpec(cell_id=10, plmn="525-05", tac=3001, si_periodicity=8),
        CellSpec(cell_id=11, plmn="525-05", tac=3001, si_periodicity=8),
        CellSpec(cell_id=12, plmn="525-05", tac=3001, si_periodicity=8),
        CellSpec(cell_id=13, plmn="525-05", tac=3001, si_periodicity=8),
        CellSpec(cell_id=99, plmn="525-05", tac=3001, si_periodicity=64),
    ]
    pagings = []
    return Pattern(name="si_periodicity_outlier", cells=cells, pagings=pagings)


def all_patterns() -> list[Pattern]:
    return [
        pattern_unknown_plmn(),
        pattern_plmn_mismatch_in_tac(),
        pattern_excessive_stmsi_churn(),
        pattern_imsi_paging_storm(),
        pattern_si_periodicity_outlier(),
    ]


# ---- writer -----------------------------------------------------------


def materialize(pattern: Pattern, db: CaptureDB,
                *, base_ts_us: int | None = None) -> int:
    """Insert pattern's cells + pagings into ``db``. Returns the number
    of paging rows written."""
    base = base_ts_us if base_ts_us is not None else int(time.time() * 1e6)

    for c in pattern.cells:
        try:
            mcc, mnc = c.plmn.split("-")
        except ValueError:
            continue
        sib1 = SIB1(
            plmns=[PLMN(mcc=mcc, mnc=mnc)],
            tracking_area_code=c.tac,
            cell_id=c.cell_id,
            si_periodicity=c.si_periodicity,
        )
        db.insert_cell(sib1, cell_id=c.cell_id, ts_us=base)

    for i, p in enumerate(pattern.pagings):
        rec = PagingRecord(
            kind=p.kind, cn_domain="ps",
            imsi=p.imsi, mmec=p.mmec, m_tmsi=p.m_tmsi,
        )
        ts = p.ts_us if p.ts_us is not None else base + i * 1000
        db.insert_paging(rec, ts_us=ts, cell_id=p.cell_id)

    return len(pattern.pagings)


def materialize_many(
    patterns: Iterable[Pattern],
    db: CaptureDB,
) -> dict[str, int]:
    out: dict[str, int] = {}
    for p in patterns:
        out[p.name] = materialize(p, db)
    return out


# ---- random valid PCCH for fuzzing --------------------------------------


def random_imsi() -> str:
    digits = [secrets.randbelow(10) for _ in range(15)]
    # MCC must be three digits, ensure first nonzero so it parses.
    digits[0] = (digits[0] % 9) + 1
    return "".join(str(d) for d in digits)


def random_paging_record(kind: str | None = None) -> PagingRecord:
    if kind is None:
        kind = "imsi" if secrets.randbelow(2) else "s-tmsi"
    if kind == "imsi":
        return PagingRecord(kind="imsi", cn_domain="ps", imsi=random_imsi())
    return PagingRecord(
        kind="s-tmsi", cn_domain="ps",
        mmec=secrets.randbelow(256),
        m_tmsi=secrets.randbits(32),
    )
