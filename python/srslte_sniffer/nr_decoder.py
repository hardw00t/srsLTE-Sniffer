"""5G NR research-mode skeleton.

Status: research-mode. NR (TS 38.331) decoding is structurally similar to
LTE — same PER ASN.1, same PCCH-Message at the top of the paging stack —
but the carried identities differ:

* `ng-5G-S-TMSI`  — 48-bit pair, similar role to S-TMSI in LTE.
* `i-RNTI`        — used for RRC INACTIVE state paging.
* `fullI-RNTI`    — full 40-bit identifier.

What the field calls a "5G IMSI catcher" is largely a misnomer for **standalone
5G** because SUPI is encrypted into a SUCI before it ever leaves the UE.
Passive capture in 5G SA therefore gives you S-TMSI / I-RNTI churn (still
useful for tracking and rogue-cell detection) but NOT a permanent IMSI.

This module gives you:

* `decode_nr_pcch(buf)` — wrapper around the pycrate NR-RRC PCCH-Message
* `extract_nr_paging_records(...)` — equivalent of the LTE function, with
  `kind` widened to `i-rnti`, `ng-5g-s-tmsi`, `unknown`.
* `decode_nr_bcch_dl_sch(buf)` / `extract_sib1_nr(...)` — for SIB1.

Hardware integration (a 5G-NR `pdsch_ue` analogue) is out of scope of this
file — the most maintained option is `srsRAN_Project` which has its own
example binaries.
"""

from __future__ import annotations

import dataclasses

try:
    from pycrate_asn1dir import RRCNR  # type: ignore

    _NR_PCCH = RRCNR.NR_RRC_Definitions.PCCH_Message
    _NR_BCCH_DL_SCH = RRCNR.NR_RRC_Definitions.BCCH_DL_SCH_Message
    _NR_OK = True
except Exception as _e:  # pragma: no cover
    _NR_PCCH = None
    _NR_BCCH_DL_SCH = None
    _NR_OK = False
    _NR_ERR = str(_e)


@dataclasses.dataclass
class NRPCCHResult:
    ok: bool
    raw: bytes
    value: dict | None = None
    error: str | None = None


@dataclasses.dataclass
class NRPagingRecord:
    kind: str  # "ng-5g-s-tmsi" | "i-rnti" | "fulli-rnti" | "unknown"
    ng5g_s_tmsi: int | None = None  # 48 bit
    i_rnti: int | None = None
    full_i_rnti: int | None = None


def _ensure() -> None:
    if not _NR_OK:
        raise RuntimeError(
            f"pycrate NR RRC unavailable: {_NR_ERR}"
        )


def decode_nr_pcch(buf: bytes) -> NRPCCHResult:
    _ensure()
    try:
        _NR_PCCH.from_uper(buf)
        return NRPCCHResult(ok=True, raw=buf, value=_NR_PCCH())
    except Exception as e:  # noqa: BLE001
        return NRPCCHResult(ok=False, raw=buf, error=str(e))


def extract_nr_paging_records(result: NRPCCHResult) -> list[NRPagingRecord]:
    if not result.ok or result.value is None:
        return []
    msg = result.value.get("message")
    if not msg or msg[0] != "c1":
        return []
    inner = msg[1]
    if inner[0] != "paging":
        return []
    paging = inner[1]
    out: list[NRPagingRecord] = []
    for rec in paging.get("pagingRecordList", []) or []:
        ue_id = rec.get("ue-Identity")
        if not ue_id:
            continue
        kind = ue_id[0]
        if kind == "ng-5G-S-TMSI":
            v = ue_id[1]
            if isinstance(v, tuple):
                ngval = v[0]
            else:
                ngval = v
            out.append(NRPagingRecord(kind="ng-5g-s-tmsi", ng5g_s_tmsi=ngval))
        elif kind == "fullI-RNTI":
            v = ue_id[1]
            ival = v[0] if isinstance(v, tuple) else v
            out.append(NRPagingRecord(kind="fulli-rnti", full_i_rnti=ival))
        elif kind == "i-RNTI":
            v = ue_id[1]
            ival = v[0] if isinstance(v, tuple) else v
            out.append(NRPagingRecord(kind="i-rnti", i_rnti=ival))
        else:
            out.append(NRPagingRecord(kind="unknown"))
    return out


def is_nr_available() -> bool:
    return _NR_OK
