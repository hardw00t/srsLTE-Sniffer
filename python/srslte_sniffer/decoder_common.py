"""Common types shared across radio generations.

The v2 LTE-only decoder uses ``PagingRecord`` etc. directly; for multi-radio
support we keep that class as the primary container but add a ``radio_type``
field and widen identifier capacity. Existing 4G code paths default
``radio_type="4g"`` so no caller breaks.

Generation conventions:
    "2g"     — GSM (GPRS-era; 2.5G included)
    "3g"     — UMTS / HSPA
    "4g"     — LTE (the v2 default)
    "5g-nsa" — 5G non-standalone (LTE control plane)
    "5g-sa"  — 5G standalone (NR control plane, SUCI not SUPI)
"""

from __future__ import annotations

import dataclasses
from typing import Literal

RadioType = Literal["2g", "3g", "4g", "5g-nsa", "5g-sa"]
ALL_RADIO_TYPES: tuple[str, ...] = (
    "2g", "3g", "4g", "5g-nsa", "5g-sa",
)


@dataclasses.dataclass
class WidePagingRecord:
    """Identifier-rich paging record for cross-generation pipelines.

    Not every field applies to every radio:
        2G  — imsi / tmsi / imei / imeisv
        3G  — imsi / p_tmsi / s_tmsi
        4G  — imsi / mmec + m_tmsi (legacy `mmec`/`m_tmsi` honoured)
        5G  — ng_5g_s_tmsi / i_rnti / full_i_rnti  (no IMSI on SA)

    Tools that don't care about radio_type can read ``imsi`` and
    ``primary_tmsi`` (a generation-agnostic 64-bit synthetic).
    """

    radio_type: RadioType
    kind: str  # "imsi" | "tmsi" | "imei" | "p-tmsi" | "s-tmsi"
               # | "ng-5g-s-tmsi" | "i-rnti" | "full-i-rnti" | "unknown"
    imsi: str | None = None
    tmsi: int | None = None
    imei: str | None = None
    imeisv: str | None = None
    p_tmsi: int | None = None
    mmec: int | None = None
    m_tmsi: int | None = None
    ng_5g_s_tmsi: int | None = None
    i_rnti: int | None = None
    full_i_rnti: int | None = None

    @property
    def primary_tmsi(self) -> int | None:
        """First non-None TMSI-class identifier — useful for cross-radio
        movement correlation regardless of generation specifics."""
        for v in (self.tmsi, self.p_tmsi, self.m_tmsi,
                  self.ng_5g_s_tmsi, self.full_i_rnti, self.i_rnti):
            if v is not None:
                return v
        return None
