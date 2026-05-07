"""ASN.1-based RRC decoders for LTE PCCH (paging) and BCCH (SIB1/2).

Replaces the original hex-pattern scanner in `parse_data.c` /
`convert_to_csv.c` with proper 3GPP TS 36.331 PCCH-Message and
BCCH-DL-SCH-Message decoders, courtesy of pycrate.

Public API:

    decode_pcch(buf: bytes) -> PCCHResult
    decode_bcch_dl_sch(buf: bytes) -> BCCHResult
    extract_paging_records(result: PCCHResult) -> list[PagingRecord]
    extract_sib1(result: BCCHResult) -> SIB1 | None
    extract_sib_container(result: BCCHResult) -> list[SIB]   # SIB2..SIB13

The functions never raise on malformed input — they return a result with
`ok=False` and the exception text instead. This is critical because over-the-air
captures contain corrupt payloads (in the demo data, ~0.01% of frames fail
PER decoding due to bit errors).
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Any

# Import pycrate generated modules lazily so the package is importable on
# systems without pycrate (e.g. for type-checking), but raise clearly when used.
try:
    # Silence pycrate's noisy ASN.1 extension warnings BEFORE importing the
    # generated RRC modules. pycrate prints them via `asnlog` (and `log`) to
    # stdout, which would otherwise corrupt JSON-emitting CLI commands. We
    # capture the same information via the exception text in the result.
    import pycrate_asn1rt.utils as _pcr_u
    import pycrate_core.utils as _pcc_u

    _pcr_u.asnlog = lambda _msg: None  # type: ignore[assignment]
    _pcr_u.log = lambda _msg: None  # type: ignore[assignment]
    _pcc_u.log = lambda _msg: None  # type: ignore[assignment]

    # Patch already-imported references in modules that did
    # `from pycrate_asn1rt.utils import asnlog`.
    import pycrate_asn1rt.asnobj_basic as _pcr_basic
    import pycrate_asn1rt.asnobj_construct as _pcr_constr

    _pcr_constr.asnlog = lambda _msg: None  # type: ignore[assignment]
    _pcr_basic.asnlog = lambda _msg: None  # type: ignore[assignment]

    from pycrate_asn1dir import RRCLTE  # type: ignore

    _PCCH = RRCLTE.EUTRA_RRC_Definitions.PCCH_Message
    _BCCH_DL_SCH = RRCLTE.EUTRA_RRC_Definitions.BCCH_DL_SCH_Message
    _PYCRATE_OK = True
except Exception as _e:  # pragma: no cover
    _PCCH = None
    _BCCH_DL_SCH = None
    _PYCRATE_OK = False
    _PYCRATE_ERR = str(_e)


@dataclasses.dataclass
class PCCHResult:
    ok: bool
    raw: bytes
    value: dict | None = None
    error: str | None = None


@dataclasses.dataclass
class BCCHResult:
    ok: bool
    raw: bytes
    value: dict | None = None
    error: str | None = None


@dataclasses.dataclass
class PagingRecord:
    """One paging record carved out of a PCCH-Message."""

    kind: str  # "imsi" | "s-tmsi" | "unknown"
    cn_domain: str | None  # "ps" | "cs"
    imsi: str | None = None  # 15-digit string when kind == "imsi"
    mmec: int | None = None  # MME code (0..255) when kind == "s-tmsi"
    m_tmsi: int | None = None  # 32-bit M-TMSI when kind == "s-tmsi"

    def hashed(self) -> PagingRecord:
        """Return a copy with identifiers SHA-256-truncated for safe storage."""
        if self.kind == "imsi" and self.imsi:
            h = hashlib.sha256(self.imsi.encode()).hexdigest()[:16]
            return dataclasses.replace(self, imsi=f"sha256:{h}")
        if self.kind == "s-tmsi" and self.m_tmsi is not None:
            h = hashlib.sha256(
                f"{self.mmec}:{self.m_tmsi}".encode()
            ).hexdigest()[:16]
            return dataclasses.replace(self, m_tmsi=None, mmec=None, imsi=f"sha256-stmsi:{h}")
        return self


@dataclasses.dataclass
class PLMN:
    mcc: str
    mnc: str

    def __str__(self) -> str:
        return f"{self.mcc}-{self.mnc}"


@dataclasses.dataclass
class SIB1:
    plmns: list[PLMN]
    tracking_area_code: int | None
    cell_id: int | None
    si_periodicity: int | None  # in radio frames


@dataclasses.dataclass
class SIB:
    """Container for SIBx (x in 2..13). We surface a small set of fields and
    keep the raw decoded value for downstream consumers."""

    sib_type: str
    raw: dict


# --- core decode -----------------------------------------------------------

def _ensure_pycrate() -> None:
    if not _PYCRATE_OK:
        raise RuntimeError(
            "pycrate is required for decoding but failed to import: "
            f"{_PYCRATE_ERR}"
        )


def decode_pcch(buf: bytes) -> PCCHResult:
    """Decode a UPER-encoded PCCH-Message. Never raises."""
    _ensure_pycrate()
    try:
        _PCCH.from_uper(buf)
        return PCCHResult(ok=True, raw=buf, value=_PCCH())
    except Exception as e:  # noqa: BLE001 — over-the-air corruption is normal
        return PCCHResult(ok=False, raw=buf, error=str(e))


def decode_bcch_dl_sch(buf: bytes) -> BCCHResult:
    """Decode a UPER-encoded BCCH-DL-SCH-Message (carries SIBs)."""
    _ensure_pycrate()
    try:
        _BCCH_DL_SCH.from_uper(buf)
        return BCCHResult(ok=True, raw=buf, value=_BCCH_DL_SCH())
    except Exception as e:  # noqa: BLE001
        return BCCHResult(ok=False, raw=buf, error=str(e))


# --- field extraction ------------------------------------------------------

def _imsi_digits_to_str(digits: list[int]) -> str:
    return "".join(str(d) for d in digits)


def extract_paging_records(result: PCCHResult) -> list[PagingRecord]:
    """Carve PagingRecord objects out of a decoded PCCH-Message.

    Handles the full set of co-frame layouts the original C code couldn't
    reliably parse (multiple records, S-TMSI before/after IMSI, etc.) — they
    all fall out of the structured representation for free.
    """
    if not result.ok or result.value is None:
        return []
    msg = result.value.get("message")
    if not msg or msg[0] != "c1":
        return []
    inner = msg[1]
    if inner[0] != "paging":
        return []
    paging = inner[1]
    out: list[PagingRecord] = []
    for rec in paging.get("pagingRecordList", []) or []:
        ue_id = rec.get("ue-Identity")
        if not ue_id:
            continue
        cn = rec.get("cn-Domain")
        if ue_id[0] == "imsi":
            digits = ue_id[1]
            out.append(
                PagingRecord(
                    kind="imsi",
                    cn_domain=cn,
                    imsi=_imsi_digits_to_str(digits),
                )
            )
        elif ue_id[0] == "s-TMSI":
            stmsi = ue_id[1]
            mmec_val, _mmec_bits = stmsi.get("mmec", (None, None))
            mtmsi_val, _mtmsi_bits = stmsi.get("m-TMSI", (None, None))
            out.append(
                PagingRecord(
                    kind="s-tmsi",
                    cn_domain=cn,
                    mmec=mmec_val,
                    m_tmsi=mtmsi_val,
                )
            )
        else:
            out.append(PagingRecord(kind="unknown", cn_domain=cn))
    return out


def _decode_plmn(plmn_struct: dict) -> PLMN:
    """3GPP MCC/MNC carrying. MNC is 2 or 3 digits."""
    mcc_digits = plmn_struct.get("mcc") or []
    mnc_digits = plmn_struct.get("mnc") or []
    return PLMN(
        mcc="".join(str(d) for d in mcc_digits),
        mnc="".join(str(d) for d in mnc_digits),
    )


def extract_sib1(result: BCCHResult) -> SIB1 | None:
    """Pull SIB1 out of a BCCH-DL-SCH-Message — None if message isn't SIB1."""
    if not result.ok or result.value is None:
        return None
    msg = result.value.get("message")
    if not msg or msg[0] != "c1":
        return None
    inner = msg[1]
    if inner[0] != "systemInformationBlockType1":
        return None
    sib1 = inner[1]

    plmns: list[PLMN] = []
    for plmn_id in sib1.get("cellAccessRelatedInfo", {}).get(
        "plmn-IdentityList", []
    ) or []:
        plmn_struct = plmn_id.get("plmn-Identity")
        if plmn_struct:
            plmns.append(_decode_plmn(plmn_struct))

    cell_access = sib1.get("cellAccessRelatedInfo", {})
    tac_val = cell_access.get("trackingAreaCode")
    if isinstance(tac_val, tuple):
        tac_int = tac_val[0]
    else:
        tac_int = tac_val
    cell_val = cell_access.get("cellIdentity")
    if isinstance(cell_val, tuple):
        cell_int = cell_val[0]
    else:
        cell_int = cell_val

    sched_info = sib1.get("schedulingInfoList", []) or []
    si_period = None
    if sched_info:
        si_period_str = sched_info[0].get("si-Periodicity")
        # Encoded as "rf8" .. "rf512" — strip prefix, parse int.
        if isinstance(si_period_str, str) and si_period_str.startswith("rf"):
            try:
                si_period = int(si_period_str[2:])
            except ValueError:
                si_period = None

    return SIB1(
        plmns=plmns,
        tracking_area_code=tac_int,
        cell_id=cell_int,
        si_periodicity=si_period,
    )


def extract_sib_container(result: BCCHResult) -> list[SIB]:
    """Pull each sib-TypeAndInfo entry out of a SystemInformation message.

    SIB2..SIB13 ride inside a `SystemInformation` message (not SIB1 — SIB1 has
    its own top-level alternative). This addresses the long-standing TODO in
    the original `cell_measurement.c` for SIB2 capture.
    """
    if not result.ok or result.value is None:
        return []
    msg = result.value.get("message")
    if not msg or msg[0] != "c1":
        return []
    inner = msg[1]
    if inner[0] != "systemInformation":
        return []
    si = inner[1]
    crit_ext = si.get("criticalExtensions")
    if not crit_ext or crit_ext[0] != "systemInformation-r8":
        return []
    payload = crit_ext[1]
    sibs: list[SIB] = []
    for entry in payload.get("sib-TypeAndInfo", []) or []:
        # Each entry is a CHOICE ('sib2', dict) / ('sib3', dict) / ...
        if isinstance(entry, tuple) and len(entry) == 2:
            sibs.append(SIB(sib_type=entry[0], raw=entry[1] if isinstance(entry[1], dict) else {}))
    return sibs


# --- convenience -----------------------------------------------------------

def summarize(records: list[PagingRecord]) -> dict[str, Any]:
    """Cheap stats useful for tests and the dashboard."""
    return {
        "total": len(records),
        "imsi": sum(1 for r in records if r.kind == "imsi"),
        "s_tmsi": sum(1 for r in records if r.kind == "s-tmsi"),
        "unknown": sum(1 for r in records if r.kind == "unknown"),
    }
