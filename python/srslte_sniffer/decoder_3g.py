"""3G UMTS PCCH paging decoder.

Wraps pycrate's TS 25.331 RRC ASN.1 PER decoder. Identity types in 3G:

- imsi-GSM-MAP   — 15 BCD digits (the same as on the SIM)
- tmsi-GSM-MAP   — 32-bit BIT STRING
- p-TMSI-GSM-MAP — 32-bit BIT STRING (packet TMSI)
- imsi-DS-41     — CDMA2000 carrier
- tmsi-DS-41     — CDMA2000 carrier
- u-RNTI         — UTRAN-internal radio identity (utran-Identity branch)

For our use case (IMSI catcher / rogue-cell detection) we surface the
GSM-MAP variants via WidePagingRecord. DS-41 fields are still parsed
but exposed as raw bytes — operators in CDMA2000 markets can wire them
up if needed.

Notes:
- pycrate's noisy logging is silenced via the same hook used by the LTE
  decoder (decoder.py).
- Multi-record paging frames are normal in UMTS; the helper returns one
  WidePagingRecord per record.
"""

from __future__ import annotations

import dataclasses

from .decoder_common import WidePagingRecord

try:
    # Same logging silencer as the LTE side — see decoder.py for rationale.
    import pycrate_asn1rt.asnobj_basic as _pcr_basic
    import pycrate_asn1rt.asnobj_construct as _pcr_constr
    import pycrate_asn1rt.utils as _pcr_u

    for _mod in (_pcr_u, _pcr_constr, _pcr_basic):
        if hasattr(_mod, "asnlog"):
            _mod.asnlog = lambda _msg: None  # type: ignore[assignment]
        if hasattr(_mod, "log"):
            _mod.log = lambda _msg: None  # type: ignore[assignment]

    from pycrate_asn1dir import RRC3G  # type: ignore

    _PCCH = RRC3G.Class_definitions.PCCH_Message
    _OK = True
except Exception as _e:  # pragma: no cover
    _PCCH = None
    _OK = False
    _ERR = str(_e)


@dataclasses.dataclass
class PCCH3GResult:
    ok: bool
    raw: bytes
    value: dict | None = None
    error: str | None = None


def is_available() -> bool:
    return _OK


def decode_pcch(buf: bytes) -> PCCH3GResult:
    if not _OK:
        return PCCH3GResult(
            ok=False, raw=buf,
            error=f"pycrate RRC3G unavailable: {_ERR}",
        )
    try:
        _PCCH.from_uper(buf)
        return PCCH3GResult(ok=True, raw=buf, value=_PCCH())
    except Exception as e:  # noqa: BLE001
        return PCCH3GResult(ok=False, raw=buf, error=str(e))


def _bitstring_to_int(bs) -> int | None:
    """pycrate represents BIT STRINGs as (int_value, num_bits)."""
    if isinstance(bs, tuple) and len(bs) == 2 and isinstance(bs[0], int):
        return bs[0]
    if isinstance(bs, bytes):
        return int.from_bytes(bs, "big")
    return None


def _imsi_to_str(digits) -> str | None:
    if digits is None:
        return None
    try:
        return "".join(str(int(d)) for d in digits)
    except (TypeError, ValueError):
        return None


def extract_paging_records(result: PCCH3GResult) -> list[WidePagingRecord]:
    """Walk the decoded value and emit one WidePagingRecord per UE
    identity. Returns ``[]`` on decode failure or unsupported message
    structure."""
    if not result.ok or result.value is None:
        return []
    msg = result.value.get("message")
    if not msg or msg[0] != "pagingType1":
        return []
    paging = msg[1]
    out: list[WidePagingRecord] = []
    for rec in paging.get("pagingRecordList", []) or []:
        if rec[0] == "cn-Identity":
            cn = rec[1]
            ue = cn.get("cn-pagedUE-Identity")
            if not ue:
                continue
            tag, val = ue
            if tag == "imsi-GSM-MAP":
                out.append(WidePagingRecord(
                    radio_type="3g", kind="imsi",
                    imsi=_imsi_to_str(val),
                ))
            elif tag == "tmsi-GSM-MAP":
                t = _bitstring_to_int(val)
                if t is not None:
                    out.append(WidePagingRecord(
                        radio_type="3g", kind="tmsi", tmsi=t,
                    ))
            elif tag == "p-TMSI-GSM-MAP":
                t = _bitstring_to_int(val)
                if t is not None:
                    out.append(WidePagingRecord(
                        radio_type="3g", kind="p-tmsi", p_tmsi=t,
                    ))
            elif tag == "imsi-DS-41":
                # CDMA2000 — surface as imsi field on best-effort decode.
                if isinstance(val, bytes):
                    out.append(WidePagingRecord(
                        radio_type="3g", kind="imsi",
                        imsi=val.hex(),
                    ))
            else:
                out.append(WidePagingRecord(
                    radio_type="3g", kind="unknown",
                ))
        elif rec[0] == "utran-Identity":
            # U-RNTI — UTRAN-internal identity, not a permanent ID.
            out.append(WidePagingRecord(
                radio_type="3g", kind="unknown",
            ))
    return out
