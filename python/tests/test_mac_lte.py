"""MAC-LTE pseudo-header decoder tests."""

from __future__ import annotations

from srslte_sniffer.mac_lte import parse_mac_lte_header
from srslte_sniffer.pcap_io import PAGING_HEADER, SIB1_HEADER, SIB2_HEADER


def test_parse_paging_header():
    h = parse_mac_lte_header(PAGING_HEADER)
    assert h is not None
    assert h.rnti_kind == "p-rnti"
    assert h.rnti == 0xFFFE
    assert h.channel == "pcch"


def test_parse_sib1_header():
    h = parse_mac_lte_header(SIB1_HEADER)
    assert h is not None
    assert h.channel == "sib1"


def test_parse_sib2_header():
    h = parse_mac_lte_header(SIB2_HEADER)
    assert h is not None
    assert h.channel == "sib2"


def test_rejects_garbage():
    assert parse_mac_lte_header(b"\x00" * 15) is None
    assert parse_mac_lte_header(b"\x01\x01") is None  # too short


def test_rnti_extraction():
    custom = bytearray(PAGING_HEADER)
    custom[4] = 0x12
    custom[5] = 0x34
    h = parse_mac_lte_header(bytes(custom))
    assert h.rnti == 0x1234
