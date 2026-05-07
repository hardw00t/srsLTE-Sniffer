"""2G GSM RR Paging Request decoder tests.

Test vectors are hand-built from TS 04.18 §9.1.22 — small enough to
verify by inspection, enough variety to exercise each branch.
"""

from __future__ import annotations

from srslte_sniffer.decoder_2g import (
    MT_PAGING_TYPE_1,
    MT_PAGING_TYPE_2,
    MT_PAGING_TYPE_3,
    decode_paging,
    extract_records,
)


def _hdr(msg_type: int) -> bytes:
    # PD=RR (0x06) + message type + page-mode/channels-needed byte
    return bytes([0x06, msg_type, 0x00])


def test_paging_type_1_with_tmsi():
    # MI: type-3 IE (length-value, no IEI). Type-of-identity = 4 (TMSI),
    # 4-byte TMSI follows.
    mi_value = bytes([0xF4, 0xCA, 0xFE, 0xBA, 0xBE])  # F = filler, type=4
    pkt = _hdr(MT_PAGING_TYPE_1) + bytes([len(mi_value)]) + mi_value
    res = decode_paging(pkt)
    assert res.ok, res.error
    recs = extract_records(res)
    assert len(recs) == 1
    r = recs[0]
    assert r.kind == "tmsi"
    assert r.tmsi == 0xCAFEBABE
    assert r.radio_type == "2g"


def test_paging_type_1_with_imsi():
    # IMSI: 525058131997813 (15 digits, odd length → odd_even=1).
    # Per TS 24.008 §10.5.1.4, the first MI value byte is:
    #   bits 1-3: type-of-identity (1=IMSI)
    #   bit 4:    odd/even (1 here)
    #   bits 5-8: digit 1
    # Subsequent bytes carry pairs of digits with the LOW nibble being
    # the EARLIER digit:
    #   byte 1 = (d3 << 4) | d2
    #   byte 2 = (d5 << 4) | d4  ...
    # IMSI = 5,2,5,0,5,8,1,3,1,9,9,7,8,1,3
    mi = bytes([
        0x59,  # type=1 odd=1 d1=5 → 0x59
        0x52,  # d3=5 d2=2
        0x05,  # d5=0 d4=5  -> wait, this is (d5<<4)|d4 = (5<<4)|0 = 0x50
              # Actually: d5=5 d4=0 → 0x50. Let me recompute.
    ])
    # Recompute by hand for clarity:
    digits = [5, 2, 5, 0, 5, 8, 1, 3, 1, 9, 9, 7, 8, 1, 3]
    flag_byte = (digits[0] << 4) | (1 << 3) | 1  # d1, odd_even=1, type=1
    mi_bytes = [flag_byte]
    for i in range(1, len(digits), 2):
        if i + 1 < len(digits):
            mi_bytes.append((digits[i + 1] << 4) | digits[i])
        else:
            # Odd length — last byte high nibble is the final digit, low
            # nibble irrelevant in odd_even=1 since we have a complete
            # pairing already.
            mi_bytes.append(digits[i])
    mi = bytes(mi_bytes)

    pkt = _hdr(MT_PAGING_TYPE_1) + bytes([len(mi)]) + mi
    res = decode_paging(pkt)
    assert res.ok, res.error
    recs = extract_records(res)
    assert len(recs) == 1
    assert recs[0].kind == "imsi"
    assert recs[0].imsi == "525058131997813"


def test_paging_type_1_with_two_identities():
    mi1 = bytes([0xF4, 0x01, 0x02, 0x03, 0x04])
    mi2 = bytes([0xF4, 0x05, 0x06, 0x07, 0x08])
    pkt = (_hdr(MT_PAGING_TYPE_1)
           + bytes([len(mi1)]) + mi1
           + bytes([0x17])  # IEI of MI 2
           + bytes([len(mi2)]) + mi2)
    res = decode_paging(pkt)
    assert res.ok, res.error
    recs = extract_records(res)
    assert [r.tmsi for r in recs] == [0x01020304, 0x05060708]


def test_paging_type_2_two_tmsis():
    pkt = _hdr(MT_PAGING_TYPE_2) + bytes([
        0xDE, 0xAD, 0xBE, 0xEF,
        0xCA, 0xFE, 0xBA, 0xBE,
    ])
    res = decode_paging(pkt)
    assert res.ok, res.error
    recs = extract_records(res)
    assert [r.tmsi for r in recs] == [0xDEADBEEF, 0xCAFEBABE]


def test_paging_type_3_four_tmsis():
    pkt = _hdr(MT_PAGING_TYPE_3) + bytes([
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x03,
        0x00, 0x00, 0x00, 0x04,
    ])
    res = decode_paging(pkt)
    assert res.ok, res.error
    recs = extract_records(res)
    assert [r.tmsi for r in recs] == [1, 2, 3, 4]


def test_too_short_input_safe():
    res = decode_paging(b"")
    assert not res.ok
    assert "too short" in (res.error or "")


def test_wrong_protocol_disc_rejected():
    res = decode_paging(bytes([0x07, MT_PAGING_TYPE_1, 0x00]))
    assert not res.ok
    assert "protocol-discriminator" in (res.error or "")


def test_unknown_message_type_rejected():
    res = decode_paging(bytes([0x06, 0x99, 0x00]))
    assert not res.ok


def test_truncated_payload_safe():
    # Type-3 expects 16 bytes of TMSI but only get 6
    pkt = _hdr(MT_PAGING_TYPE_3) + bytes([0x00] * 6)
    res = decode_paging(pkt)
    # Should not raise; either ok with partial extra_tmsis or graceful fail.
    recs = extract_records(res)
    # Whatever we extracted should be coherent integers.
    assert all(isinstance(r.tmsi, int) for r in recs if r.kind == "tmsi")
