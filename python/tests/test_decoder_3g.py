"""3G UMTS PCCH paging decoder tests."""

from __future__ import annotations

import pytest

from srslte_sniffer import decoder_3g


@pytest.mark.skipif(not decoder_3g.is_available(),
                    reason="pycrate RRC3G unavailable")
def test_decode_invalid_returns_error_not_raise():
    res = decoder_3g.decode_pcch(b"\x00")
    assert isinstance(res.ok, bool)


@pytest.mark.skipif(not decoder_3g.is_available(),
                    reason="pycrate RRC3G unavailable")
def test_extract_on_failed_result_is_empty():
    res = decoder_3g.decode_pcch(b"\xff\xff\xff\xff" * 100)
    recs = decoder_3g.extract_paging_records(res)
    assert recs == []


@pytest.mark.skipif(not decoder_3g.is_available(),
                    reason="pycrate RRC3G unavailable")
def test_decode_synthesized_tmsi_paging():
    """Build a real PCCH-Message with a TMSI-GSM-MAP record via pycrate,
    encode it, then decode it through our decoder and check we recover
    the TMSI value."""
    from pycrate_asn1dir import RRC3G

    PCCH = RRC3G.Class_definitions.PCCH_Message
    val = {"message": ("pagingType1", {
        "pagingRecordList": [
            ("cn-Identity", {
                "pagingCause": "terminatingConversationalCall",
                "cn-DomainIdentity": "cs-domain",
                "cn-pagedUE-Identity": ("tmsi-GSM-MAP", (0xCAFEBABE, 32)),
            }),
        ],
        "bcch-ModificationInfo": {
            "mib-ValueTag": 1,
            "bcch-ModificationTime": 0,
        },
        "laterNonCriticalExtensions": {},
    })}
    PCCH.set_val(val)
    encoded = PCCH.to_uper()

    res = decoder_3g.decode_pcch(encoded)
    assert res.ok, res.error
    recs = decoder_3g.extract_paging_records(res)
    assert len(recs) == 1
    assert recs[0].radio_type == "3g"
    assert recs[0].kind == "tmsi"
    assert recs[0].tmsi == 0xCAFEBABE


@pytest.mark.skipif(not decoder_3g.is_available(),
                    reason="pycrate RRC3G unavailable")
def test_decode_synthesized_imsi_paging():
    """Round-trip an IMSI paging."""
    from pycrate_asn1dir import RRC3G

    PCCH = RRC3G.Class_definitions.PCCH_Message
    digits = [3, 1, 0, 1, 5, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    val = {"message": ("pagingType1", {
        "pagingRecordList": [
            ("cn-Identity", {
                "pagingCause": "terminatingConversationalCall",
                "cn-DomainIdentity": "cs-domain",
                "cn-pagedUE-Identity": ("imsi-GSM-MAP", digits),
            }),
        ],
        "bcch-ModificationInfo": {
            "mib-ValueTag": 1,
            "bcch-ModificationTime": 0,
        },
        "laterNonCriticalExtensions": {},
    })}
    PCCH.set_val(val)
    encoded = PCCH.to_uper()

    res = decoder_3g.decode_pcch(encoded)
    assert res.ok, res.error
    recs = decoder_3g.extract_paging_records(res)
    assert len(recs) == 1
    assert recs[0].kind == "imsi"
    assert recs[0].imsi == "310150123456789"
