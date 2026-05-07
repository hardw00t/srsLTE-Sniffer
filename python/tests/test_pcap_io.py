"""I/O tests — text reader, legacy pcap reader, pcapng writer."""

from __future__ import annotations

from pathlib import Path

import pytest

from srslte_sniffer.pcap_io import (PcapngWriter, classify, read_capture,
                                    read_pcap, read_text_capture)


def test_classify_paging_header():
    h = bytes.fromhex("01010102fffe030000040000070101")
    assert classify(h) == "pcch"


def test_classify_sib1_header():
    # 01 01 04 02 ff ff 03 00 00 04 09 05 07 01 01  (15 bytes)
    h = bytes.fromhex("01010402ffff030000040905070101")
    assert len(h) == 15
    assert classify(h) == "sib1"


def test_classify_sib2_header():
    # 01 01 04 02 ff ff 03 00 00 04 0a 12 07 01 01  (15 bytes)
    h = bytes.fromhex("01010402ffff030000040a12070101")
    assert len(h) == 15
    assert classify(h) == "sib2"


def test_text_capture_reads(demo_txt):
    frames = list(read_text_capture(str(demo_txt)))
    assert len(frames) > 100, "demo file is sizable"
    # First frame must be PCCH-classified and have a non-empty payload.
    f = frames[0]
    assert f.framing == "pcch"
    assert len(f.payload) > 0
    assert f.line_no == 1


def test_pcap_capture_reads(demo_pcap):
    frames = list(read_pcap(str(demo_pcap)))
    assert len(frames) > 100
    assert all(f.framing in ("pcch", "sib1", "sib2", "unknown") for f in frames)


def test_pcapng_writer_roundtrip(tmp_path: Path):
    out = tmp_path / "out.pcapng"
    pdu1 = bytes.fromhex("40016c445a8200dabf6960450000")
    pdu2 = bytes.fromhex("40016e44f355109845ff60450000")
    with PcapngWriter(out) as w:
        w.write_paging(pdu1, timestamp_us=1_000_000)
        w.write_paging(pdu2, timestamp_us=2_000_000)
    raw = out.read_bytes()
    # Section header block magic at the very start.
    assert raw[:4] == b"\x0a\x0d\x0d\x0a"
    # Should contain at least two EPB blocks (type 0x06)
    epb_count = raw.count(b"\x06\x00\x00\x00")
    assert epb_count >= 2


def test_read_capture_autodetect_text(demo_txt):
    frames = list(read_capture(str(demo_txt)))
    assert len(frames) > 0


def test_read_capture_autodetect_pcap(demo_pcap):
    frames = list(read_capture(str(demo_pcap)))
    assert len(frames) > 0
