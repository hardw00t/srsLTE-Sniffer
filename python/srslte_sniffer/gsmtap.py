"""GSMTAP encapsulation for 2G/3G captures.

GSMTAP is the de-facto open format for raw cellular radio messages. Used
by gr-gsm, Osmocom, srsRAN test tooling, and Wireshark's `gsmtap`
dissector. Output is one UDP-shaped packet per radio frame, written into
pcapng with link-layer type 197 (DLT_GSMTAP).

Header layout (TS 02.18 informal, Wireshark `packet-gsmtap.h`):
    u8  version = 0x02
    u8  hdr_len = 4 (in 32-bit words)
    u8  type    (1=GSM_UM, 2=GSM_ABIS, 3=GSM_UM_BURST, 4=SIM, 7=UMTS_RRC, ...)
    u8  timeslot
    u16 arfcn (with PCS/uplink flags in top bits — we leave 0 for unknowns)
    s8  signal_dbm
    s8  snr_db
    u32 frame_number
    u8  sub_type (sub-channel, depends on `type`)
    u8  antenna_nr
    u8  sub_slot
    u8  res

The Python writer here is the analytical counterpart of
`pcap_io.PcapngWriter` — same SHB/IDB/EPB block plumbing, but:
    - link_type = 197 (DLT_GSMTAP_DARWIN — the one Wireshark accepts as
      raw GSMTAP)
    - per-packet body is the GSMTAP header followed by the L2/L3 PDU.
"""

from __future__ import annotations

import struct

from .pcap_io import PcapngWriter

DLT_GSMTAP = 197

# GSMTAP type values (excerpt — full list in Wireshark headers).
GSMTAP_TYPE_UM         = 0x01  # GSM Um frame
GSMTAP_TYPE_GSM_RLC    = 0x06
GSMTAP_TYPE_UMTS_RRC   = 0x0c
GSMTAP_TYPE_LTE_RRC    = 0x0d
GSMTAP_TYPE_LTE_MAC    = 0x0e
GSMTAP_TYPE_LTE_MAC_FRAMED = 0x0f
GSMTAP_TYPE_OSMOCORE_LOG   = 0x10

# GSM channel types (sub_type for GSMTAP_TYPE_UM)
GSMTAP_CHAN_BCCH       = 0x01
GSMTAP_CHAN_CCCH       = 0x02
GSMTAP_CHAN_PCH        = 0x04   # paging channel (downlink)
GSMTAP_CHAN_AGCH       = 0x06

# UMTS RRC channel types
GSMTAP_RRC_PCCH        = 0x09
GSMTAP_RRC_BCCH_BCH    = 0x07
GSMTAP_RRC_BCCH_FACH   = 0x08
GSMTAP_RRC_DL_DCCH     = 0x0c

GSMTAP_HDR_FMT = "!BBBBHbbI4B"
assert struct.calcsize(GSMTAP_HDR_FMT) == 16


def build_header(*,
                 type_: int,
                 sub_type: int,
                 timeslot: int = 0,
                 arfcn: int = 0,
                 signal_dbm: int = 0,
                 snr_db: int = 0,
                 frame_number: int = 0,
                 antenna_nr: int = 0,
                 sub_slot: int = 0) -> bytes:
    return struct.pack(
        GSMTAP_HDR_FMT,
        0x02,                  # version
        4,                     # hdr_len in 32-bit words
        type_, timeslot,
        arfcn, signal_dbm, snr_db,
        frame_number,
        sub_type, antenna_nr, sub_slot, 0,
    )


class GsmtapWriter:
    """Convenience: pcapng + DLT 197 + GSMTAP header on every packet.

    The underlying pcapng SHB/IDB/EPB plumbing is shared with PcapngWriter
    so all the existing readers Just Work — we only change the link type.
    """

    def __init__(self, path) -> None:
        self._inner = PcapngWriter(path, link_type=DLT_GSMTAP)

    def __enter__(self) -> GsmtapWriter:
        self._inner.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        self._inner.__exit__(*exc)

    def write_gsm_pch(self, l3_pdu: bytes, *,
                      arfcn: int = 0,
                      frame_number: int = 0,
                      timestamp_us: int | None = None) -> None:
        hdr = build_header(
            type_=GSMTAP_TYPE_UM,
            sub_type=GSMTAP_CHAN_PCH,
            arfcn=arfcn, frame_number=frame_number,
        )
        self._inner.write_packet(hdr + l3_pdu, timestamp_us=timestamp_us)

    def write_umts_pcch(self, pdu: bytes, *,
                        arfcn: int = 0,
                        frame_number: int = 0,
                        timestamp_us: int | None = None) -> None:
        hdr = build_header(
            type_=GSMTAP_TYPE_UMTS_RRC,
            sub_type=GSMTAP_RRC_PCCH,
            arfcn=arfcn, frame_number=frame_number,
        )
        self._inner.write_packet(hdr + pdu, timestamp_us=timestamp_us)


def parse_header(buf: bytes) -> dict | None:
    """Return a dict with the GSMTAP header fields, or None if invalid."""
    if len(buf) < 16:
        return None
    fields = struct.unpack(GSMTAP_HDR_FMT, buf[:16])
    version, hdr_len, type_, timeslot, arfcn, sig, snr, fn, sub, ant, sub_slot, _ = fields
    if version != 0x02:
        return None
    return {
        "version": version,
        "type": type_,
        "sub_type": sub,
        "timeslot": timeslot,
        "arfcn": arfcn,
        "signal_dbm": sig,
        "snr_db": snr,
        "frame_number": fn,
        "antenna_nr": ant,
        "sub_slot": sub_slot,
    }
