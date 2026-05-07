"""Decoder tests against real captures and crafted edge cases."""

from __future__ import annotations

from srslte_sniffer.decoder import (
    decode_pcch,
    extract_paging_records,
    summarize,
)


# Two captured payloads from imsi_pcap_demo.txt — first record is a
# single S-TMSI, second is also S-TMSI. Hand-verified.
SAMPLE_STMSI_1 = bytes.fromhex("40016c445a8200dabf6960450000")
SAMPLE_STMSI_2 = bytes.fromhex("40016e44f355109845ff60450000")


def test_decode_single_stmsi():
    res = decode_pcch(SAMPLE_STMSI_1)
    assert res.ok, res.error
    recs = extract_paging_records(res)
    assert len(recs) == 1
    r = recs[0]
    assert r.kind == "s-tmsi"
    assert r.mmec == 0x16
    assert r.m_tmsi == 0xC445A820
    assert r.cn_domain == "ps"


def test_decode_invalid_returns_error_not_raise():
    res = decode_pcch(b"\x00" * 4)  # too short / nonsense
    # MUST NOT raise
    assert res.ok is False or len(extract_paging_records(res)) == 0


def test_summarize():
    res1 = decode_pcch(SAMPLE_STMSI_1)
    res2 = decode_pcch(SAMPLE_STMSI_2)
    recs = extract_paging_records(res1) + extract_paging_records(res2)
    s = summarize(recs)
    assert s["total"] == 2
    assert s["s_tmsi"] == 2
    assert s["imsi"] == 0


def test_hashed_redacts_imsi():
    from srslte_sniffer.decoder import PagingRecord

    r = PagingRecord(kind="imsi", cn_domain="ps", imsi="525058131997813")
    h = r.hashed()
    assert h.imsi != r.imsi
    assert h.imsi.startswith("sha256:")


def test_hashed_redacts_stmsi():
    from srslte_sniffer.decoder import PagingRecord

    r = PagingRecord(kind="s-tmsi", cn_domain="ps", mmec=22, m_tmsi=0xC445A820)
    h = r.hashed()
    assert h.mmec is None
    assert h.m_tmsi is None
    assert h.imsi.startswith("sha256-stmsi:")
