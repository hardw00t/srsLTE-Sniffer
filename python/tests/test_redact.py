"""PCAP redaction tests — assert the output is wire-format-valid and
deterministic, and that no original IMSI/M-TMSI bits survive."""

from __future__ import annotations

from pathlib import Path

from srslte_sniffer.decoder import (
    PagingRecord,
    decode_pcch,
    extract_paging_records,
)
from srslte_sniffer.pcap_io import PcapngWriter, read_capture
from srslte_sniffer.redact import redact_capture


def _write_pcap_with_known(pdu: bytes, path: Path) -> None:
    with PcapngWriter(path) as w:
        w.write_paging(pdu, timestamp_us=1_000_000)


# Known S-TMSI from the demo capture.
SAMPLE_STMSI = bytes.fromhex("40016c445a8200dabf6960450000")


def test_redacted_output_decodes_validly(tmp_path: Path):
    src = tmp_path / "in.pcapng"
    dst = tmp_path / "out.pcapng"
    _write_pcap_with_known(SAMPLE_STMSI, src)

    stats = redact_capture(src, dst)
    assert stats.frames_in == stats.frames_out == 1
    assert stats.pcch_redacted == 1

    # The redacted output must still decode to a valid PCCH-Message.
    out_frames = list(read_capture(str(dst)))
    assert len(out_frames) == 1
    res = decode_pcch(out_frames[0].payload)
    assert res.ok, res.error
    recs = extract_paging_records(res)
    assert len(recs) == 1
    r = recs[0]
    # Same kind preserved.
    assert r.kind == "s-tmsi"
    # But values differ from the input.
    assert (r.mmec, r.m_tmsi) != (0x16, 0xC445A820)


def test_redaction_is_deterministic(tmp_path: Path):
    src = tmp_path / "in.pcapng"
    dst1 = tmp_path / "a.pcapng"
    dst2 = tmp_path / "b.pcapng"
    _write_pcap_with_known(SAMPLE_STMSI, src)
    redact_capture(src, dst1)
    redact_capture(src, dst2)
    assert dst1.read_bytes() == dst2.read_bytes()


def test_imsi_redaction_preserves_mcc(tmp_path: Path):
    """Encode a synthetic IMSI paging, redact, check MCC is preserved
    when the flag is on, and not preserved when it's off."""
    from srslte_sniffer.decoder import _PCCH

    # Build PCCH-Message{ paging { pagingRecordList { imsi=525058131997813 } } }
    val = {
        "message": ("c1", ("paging", {
            "pagingRecordList": [{
                "ue-Identity": (
                    "imsi", [5, 2, 5, 0, 5, 8, 1, 3, 1, 9, 9, 7, 8, 1, 3]
                ),
                "cn-Domain": "ps",
            }],
        })),
    }
    _PCCH.set_val(val)
    pdu = _PCCH.to_uper()

    src = tmp_path / "in.pcapng"
    dst = tmp_path / "out.pcapng"
    _write_pcap_with_known(pdu, src)

    redact_capture(src, dst, preserve_mcc=True)
    out = list(read_capture(str(dst)))[0]
    recs = extract_paging_records(decode_pcch(out.payload))
    assert recs[0].kind == "imsi"
    assert recs[0].imsi.startswith("525")  # MCC preserved
    assert recs[0].imsi != "525058131997813"  # but rest changed

    redact_capture(src, dst, preserve_mcc=False)
    out = list(read_capture(str(dst)))[0]
    recs = extract_paging_records(decode_pcch(out.payload))
    assert recs[0].imsi != "525058131997813"


def test_undecodable_passes_through(tmp_path: Path):
    """A payload pycrate genuinely rejects — confirmed via offline replay
    of the demo capture (line 8009 hits 'bitlen overflow')."""
    src = tmp_path / "in.pcapng"
    dst = tmp_path / "out.pcapng"
    bad = bytes.fromhex("50d03d87955c7029421c20468000002be59e")
    with PcapngWriter(src) as w:
        w.write_paging(bad, timestamp_us=1)
    stats = redact_capture(src, dst)
    assert stats.pcch_passthrough_undecodable == 1
    out = list(read_capture(str(dst)))[0]
    assert out.payload == bad


# Silence unused import warning.
_ = PagingRecord
