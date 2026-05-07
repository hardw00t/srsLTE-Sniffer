"""GSMTAP encapsulation tests."""

from __future__ import annotations

from pathlib import Path

from srslte_sniffer.gsmtap import (
    DLT_GSMTAP,
    GSMTAP_CHAN_PCH,
    GSMTAP_RRC_PCCH,
    GSMTAP_TYPE_UM,
    GSMTAP_TYPE_UMTS_RRC,
    GsmtapWriter,
    build_header,
    parse_header,
)


def test_build_and_parse_header_roundtrip():
    hdr = build_header(
        type_=GSMTAP_TYPE_UM, sub_type=GSMTAP_CHAN_PCH,
        arfcn=947, frame_number=12345,
    )
    fields = parse_header(hdr)
    assert fields is not None
    assert fields["type"] == GSMTAP_TYPE_UM
    assert fields["sub_type"] == GSMTAP_CHAN_PCH
    assert fields["arfcn"] == 947
    assert fields["frame_number"] == 12345


def test_parse_header_rejects_short_buffer():
    assert parse_header(b"\x02\x04") is None


def test_parse_header_rejects_wrong_version():
    bad = bytearray(build_header(type_=GSMTAP_TYPE_UM, sub_type=0))
    bad[0] = 0xFF
    assert parse_header(bytes(bad)) is None


def test_writer_writes_pcapng_with_gsmtap_dlt(tmp_path: Path):
    p = tmp_path / "g.pcapng"
    pdu = bytes.fromhex("0621000005f400112233")  # synthetic PD=RR, MT=0x21
    with GsmtapWriter(p) as w:
        w.write_gsm_pch(pdu, arfcn=947, frame_number=42)
        w.write_umts_pcch(pdu, arfcn=10560)

    raw = p.read_bytes()
    assert raw[:4] == b"\x0a\x0d\x0d\x0a"  # SHB
    # IDB block contains the link type little-endian. DLT_GSMTAP=197=0xC5.
    assert b"\xc5\x00" in raw
    # Must contain the GSMTAP version byte 0x02 in two of the EPB
    # payloads (one per packet).
    assert raw.count(b"\x02\x04") >= 2  # version + hdr_len in 32-bit words

    # Quick sanity on the PCH and UMTS PCCH type+sub_type byte sequences:
    # PCH = type 0x01 sub_type 0x04 → bytes "\x01\x00" and somewhere "\x04"
    assert b"\x01\x00\x03\xb3" in raw  # type=UM(1) ts=0 arfcn=947(0x03B3)
    assert b"\x0c\x00\x29\x40" in raw  # type=UMTS_RRC(0x0c) arfcn=0x2940


def test_dlt_constant():
    assert DLT_GSMTAP == 197


def test_known_subtypes_present():
    # Constants should be stable; downstream tools rely on them.
    assert GSMTAP_RRC_PCCH == 0x09
    assert GSMTAP_CHAN_PCH == 0x04
