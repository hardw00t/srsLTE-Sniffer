"""2G GSM paging request decoder.

Implements the layer-3 RR Paging Request types 1/2/3 from
**3GPP TS 04.18 §9.1.22 / §9.1.23 / §9.1.24** (Wireshark calls these
``gsm_a.rr.paging_request_type_1`` etc.).

We don't depend on pycrate here — those messages are short (typical
PCH paging is ~20 bytes) and the wire format is small enough to parse
cleanly with structs. Pycrate is used elsewhere (3G/4G/5G) where the
ASN.1 weight is justified.

Public API:

    decode_paging(buf: bytes, *, msg_type: int | None = None) -> PagingResult2G
    extract_records(result) -> list[WidePagingRecord]

Input ``buf`` must be the L3 message body — meaning the GSMTAP header (if
any) has been stripped. ``decode_paging`` looks at byte 0 (proto disc) and
byte 1 (message type) to select the right type-1/2/3 layout.

Message type bytes (TS 04.18 Table 10.4):
    0x21 — RR_PAGING_REQUEST_TYPE_1   (1–2 mobile identities)
    0x22 — RR_PAGING_REQUEST_TYPE_2   (one MI + 32-bit TMSIs)
    0x24 — RR_PAGING_REQUEST_TYPE_3   (four 32-bit TMSIs)
"""

from __future__ import annotations

import dataclasses

from .decoder_common import WidePagingRecord

PD_RR = 0x06  # protocol discriminator: Radio Resources management
MT_PAGING_TYPE_1 = 0x21
MT_PAGING_TYPE_2 = 0x22
MT_PAGING_TYPE_3 = 0x24

# Mobile Identity "type of identity" (3 lsbs of the first MI byte)
MI_NONE = 0
MI_IMSI = 1
MI_IMEI = 2
MI_IMEISV = 3
MI_TMSI = 4


@dataclasses.dataclass
class PagingResult2G:
    ok: bool
    raw: bytes
    msg_type: int | None = None
    error: str | None = None
    # Decoded fields, only meaningful when ok=True
    mobile_identities: list[dict] = dataclasses.field(default_factory=list)
    extra_tmsis: list[int] = dataclasses.field(default_factory=list)


# ---- mobile identity decoder ----

def _decode_bcd_imsi(buf: bytes) -> str:
    """BCD-decode an IMSI (or IMEI). The first nibble is a flags byte
    (type-of-identity + odd/even); skip it. Bytes 1+ are pairs of
    digits, low nibble first, high nibble next."""
    if not buf:
        return ""
    odd_even = (buf[0] >> 3) & 1
    digits = []
    # The high nibble of the first byte is the first digit of the IMSI
    # (per TS 24.008 §10.5.1.4).
    digits.append(buf[0] >> 4)
    for b in buf[1:]:
        digits.append(b & 0x0F)
        digits.append(b >> 4)
    # If even number of digits, the last nibble is filler (0xF) — drop it.
    if not odd_even and digits and digits[-1] == 0xF:
        digits.pop()
    return "".join(str(d) for d in digits if d != 0xF)


def _decode_mobile_identity(buf: bytes) -> dict:
    """Decode a Mobile Identity TLV value. Returns ``{}`` on failure."""
    if not buf:
        return {}
    type_id = buf[0] & 0x07
    if type_id == MI_TMSI:
        if len(buf) < 5:
            return {}
        # The 4 bytes after the flags are the TMSI/P-TMSI.
        tmsi = int.from_bytes(buf[1:5], "big")
        return {"kind": "tmsi", "tmsi": tmsi}
    if type_id == MI_IMSI:
        return {"kind": "imsi", "imsi": _decode_bcd_imsi(buf)}
    if type_id == MI_IMEI:
        return {"kind": "imei", "imei": _decode_bcd_imsi(buf)}
    if type_id == MI_IMEISV:
        return {"kind": "imeisv", "imeisv": _decode_bcd_imsi(buf)}
    if type_id == MI_NONE:
        return {"kind": "none"}
    return {}


def decode_paging(buf: bytes, *, msg_type: int | None = None) -> PagingResult2G:
    """Decode a GSM RR Paging Request layer-3 message.

    ``msg_type`` may be passed explicitly when the caller already knows
    the type (e.g. for fuzzers); otherwise it's read from byte 1 of the
    buffer (after the protocol-discriminator byte).
    """
    if len(buf) < 2:
        return PagingResult2G(ok=False, raw=buf, error="too short")
    pd = buf[0] & 0x0F
    if pd != PD_RR:
        return PagingResult2G(
            ok=False, raw=buf,
            error=f"unexpected protocol-discriminator: 0x{pd:02x}",
        )
    if msg_type is None:
        msg_type = buf[1]
    if msg_type not in (MT_PAGING_TYPE_1, MT_PAGING_TYPE_2,
                        MT_PAGING_TYPE_3):
        return PagingResult2G(
            ok=False, raw=buf, msg_type=msg_type,
            error=f"unsupported message type: 0x{msg_type:02x}",
        )

    cur = 2  # past PD + MT
    # Skip the page-mode + channels-needed octet (1 byte for type 1/3,
    # different fields for type 2 — but byte 2 is always one octet here).
    cur += 1

    mids: list[dict] = []
    extra: list[int] = []

    try:
        if msg_type == MT_PAGING_TYPE_1:
            # Mobile Identity 1 — type-3 IE (length-value, no IEI).
            length = buf[cur]
            cur += 1
            mid_buf = buf[cur : cur + length]
            cur += length
            d = _decode_mobile_identity(mid_buf)
            if d:
                mids.append(d)
            # Optional Mobile Identity 2 — type-4 IE with IEI 0x17.
            if cur < len(buf) and buf[cur] == 0x17:
                cur += 1  # IEI
                length = buf[cur]
                cur += 1
                mid_buf = buf[cur : cur + length]
                cur += length
                d = _decode_mobile_identity(mid_buf)
                if d:
                    mids.append(d)

        elif msg_type == MT_PAGING_TYPE_2:
            # First identity is exactly a 32-bit TMSI (4 octets).
            extra.append(int.from_bytes(buf[cur : cur + 4], "big"))
            cur += 4
            # Second TMSI also 4 octets.
            if cur + 4 <= len(buf):
                extra.append(int.from_bytes(buf[cur : cur + 4], "big"))
                cur += 4
            # Optional Mobile Identity (type-4 IE with IEI 0x17) — extra UE.
            if cur < len(buf) and buf[cur] == 0x17:
                cur += 1
                length = buf[cur]
                cur += 1
                d = _decode_mobile_identity(buf[cur : cur + length])
                cur += length
                if d:
                    mids.append(d)

        elif msg_type == MT_PAGING_TYPE_3:
            # Four 32-bit TMSIs back-to-back.
            for _ in range(4):
                if cur + 4 > len(buf):
                    break
                extra.append(int.from_bytes(buf[cur : cur + 4], "big"))
                cur += 4
    except (IndexError, ValueError) as e:
        return PagingResult2G(
            ok=False, raw=buf, msg_type=msg_type,
            error=f"truncated: {e}",
        )

    return PagingResult2G(
        ok=True, raw=buf, msg_type=msg_type,
        mobile_identities=mids, extra_tmsis=extra,
    )


def extract_records(result: PagingResult2G) -> list[WidePagingRecord]:
    if not result.ok:
        return []
    out: list[WidePagingRecord] = []
    for mi in result.mobile_identities:
        kind = mi.get("kind")
        if kind == "tmsi":
            out.append(WidePagingRecord(
                radio_type="2g", kind="tmsi", tmsi=mi.get("tmsi"),
            ))
        elif kind == "imsi":
            out.append(WidePagingRecord(
                radio_type="2g", kind="imsi", imsi=mi.get("imsi"),
            ))
        elif kind == "imei":
            out.append(WidePagingRecord(
                radio_type="2g", kind="imei", imei=mi.get("imei"),
            ))
        elif kind == "imeisv":
            out.append(WidePagingRecord(
                radio_type="2g", kind="imeisv", imeisv=mi.get("imeisv"),
            ))
    for t in result.extra_tmsis:
        out.append(WidePagingRecord(
            radio_type="2g", kind="tmsi", tmsi=t,
        ))
    return out
