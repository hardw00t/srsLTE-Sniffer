"""I/O for the legacy text-pcap format and proper pcapng output.

Three input formats are handled transparently:

1. Raw `.txt` capture file as written by the original `parse_data.c` —
   one packet per line, each line a hex byte stream prefixed with the
   15-byte mac-lte pseudo-header used by srsLTE.
2. `text2pcap`-converted `.pcap` (DLT 147 / "User 0") files — the format
   `loop_catcher.sh` produced.
3. The new pcapng output that `pcap_io.PcapngWriter` writes.

For output we write **pcapng** directly, eliminating the `text2pcap`
round-trip the original tool relied on.
"""

from __future__ import annotations

import dataclasses
import io
import struct
from collections.abc import Iterator
from pathlib import Path

# 15-byte MAC-LTE pseudo-header srsLTE prepends to each PCCH/SIB dump.
# Discriminator bytes (paging vs SIB1 vs SIB2) are at positions 2, 5, 10.
# These constants must agree byte-for-byte with src/pdsch_sniffer/pcap_writer.c.
PAGING_HEADER = bytes.fromhex("01010102fffe030000040000070101")
SIB1_HEADER = bytes.fromhex("01010402ffff030000040905070101")
SIB2_HEADER = bytes.fromhex("01010402ffff030000040a12070101")
HEADER_LEN = 15
assert len(PAGING_HEADER) == 15 and len(SIB1_HEADER) == 15 and len(SIB2_HEADER) == 15

# pcap link-layer types
DLT_USER0 = 147
DLT_RAW = 101


@dataclasses.dataclass
class CapturedFrame:
    """One packet as it came out of the radio."""

    payload: bytes  # the bare RRC PDU (header stripped)
    raw: bytes  # the full record as written, header included
    framing: str  # "pcch" | "sib1" | "sib2" | "unknown"
    line_no: int | None = None  # for text-format inputs
    timestamp_us: int | None = None


def classify(header: bytes) -> str:
    """Classify a 15-byte mac-lte pseudo-header.

    Discriminator bytes (matching the original parse_data.c):
        Paging:  01 01 01 02 ff fe ... 04 00 ...
        SIB1:    01 01 04 02 ff ff ... 04 09 ...
        SIB2:    01 01 04 02 ff ff ... 04 0a ...
    """
    if len(header) < HEADER_LEN:
        return "unknown"
    h = header[:HEADER_LEN]
    if h[2] == 0x01 and h[5] == 0xFE:
        return "pcch"
    if h[2] == 0x04 and h[5] == 0xFF:
        if h[10] == 0x09:
            return "sib1"
        if h[10] == 0x0A:
            return "sib2"
        return "sib1"
    return "unknown"


def read_text_capture(path: str | Path) -> Iterator[CapturedFrame]:
    """Stream-parse the `imsi.txt` / `imsi_pcap.txt` format used by parse_data.c.

    Each line is `text2pcap`-ready: optional `0000` offset prefix, then space
    separated hex bytes — the first 15 bytes are the synthetic header, the
    remainder is the RRC PDU.
    """
    path = Path(path)
    with path.open("r", errors="ignore") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            toks = line.split()
            if toks and toks[0] == "0000":
                toks = toks[1:]
            if len(toks) < HEADER_LEN + 1:
                continue
            try:
                raw = bytes.fromhex("".join(toks))
            except ValueError:
                continue
            header = raw[:HEADER_LEN]
            payload = raw[HEADER_LEN:]
            yield CapturedFrame(
                payload=payload,
                raw=raw,
                framing=classify(header),
                line_no=line_no,
            )


# --- pcap (legacy) read ----------------------------------------------------


def _read_pcap(fh: io.BufferedReader) -> Iterator[CapturedFrame]:
    magic = fh.read(4)
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError(f"not a libpcap file (magic={magic.hex()})")
    # version_major(2) version_minor(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
    fh.read(20)
    rec_hdr = struct.Struct(endian + "IIII")
    while True:
        head = fh.read(16)
        if len(head) < 16:
            return
        ts_sec, ts_usec, incl_len, _orig_len = rec_hdr.unpack(head)
        body = fh.read(incl_len)
        if len(body) < incl_len:
            return
        header = body[:HEADER_LEN]
        payload = body[HEADER_LEN:]
        yield CapturedFrame(
            payload=payload,
            raw=body,
            framing=classify(header),
            timestamp_us=ts_sec * 1_000_000 + ts_usec,
        )


def read_pcap(path: str | Path) -> Iterator[CapturedFrame]:
    with Path(path).open("rb") as fh:
        yield from _read_pcap(fh)


def _read_pcapng(fh: io.BufferedReader) -> Iterator[CapturedFrame]:
    """Minimal pcapng reader — Section Header Block + Interface Description
    Block + Enhanced Packet Blocks. Matches what PcapngWriter writes."""
    # Endianness from the SHB byte-order magic.
    fh.seek(0)
    while True:
        head = fh.read(8)
        if len(head) < 8:
            return
        bt, blen = struct.unpack("<II", head)
        if blen < 12:
            return  # corrupt
        body = fh.read(blen - 12)
        trailer = fh.read(4)
        if len(trailer) < 4:
            return
        if bt == 0x0A0D0D0A:
            # SHB — confirm BE/LE; we only emit LE so just verify.
            if len(body) >= 4:
                magic = struct.unpack("<I", body[:4])[0]
                if magic != 0x1A2B3C4D:
                    return
        elif bt == 0x00000006 and len(body) >= 20:
            # EPB: iface(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data...
            (_iface, ts_h, ts_l, cap_len, _orig) = struct.unpack(
                "<IIIII", body[:20]
            )
            data = body[20 : 20 + cap_len]
            ts_us = (ts_h << 32) | ts_l
            header = data[:HEADER_LEN]
            payload = data[HEADER_LEN:]
            yield CapturedFrame(
                payload=payload,
                raw=data,
                framing=classify(header),
                timestamp_us=ts_us,
            )
        # Other block types (IDB, etc.) are skipped silently.


def read_capture(path: str | Path) -> Iterator[CapturedFrame]:
    """Auto-detect text vs pcap vs pcapng and dispatch."""
    p = Path(path)
    with p.open("rb") as fh:
        magic = fh.read(4)
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        yield from read_pcap(p)
    elif magic == b"\n\r\r\n":
        with p.open("rb") as fh:
            yield from _read_pcapng(fh)
    elif magic[:1] == b"\n" or magic.lstrip().startswith(b"0000") or all(
        c in b"0123456789abcdefABCDEF \t\r\n" for c in magic
    ):
        yield from read_text_capture(p)
    else:
        # Last resort — try as text
        yield from read_text_capture(p)


# --- pcapng writer ---------------------------------------------------------


class PcapngWriter:
    """Minimal pcapng writer: one Section Header Block, one Interface
    Description Block, then Enhanced Packet Blocks.

    DLT 147 (User-defined Encapsulation 0) is used by Wireshark's
    `mac-lte-framed` dissector when the magic prefix `01 01 01 02 ff fe ...`
    is present, so packets land in the LTE-RRC dissector chain just like
    they did under the old `text2pcap -l 147` path — just without the
    round-trip.
    """

    PCAPNG_BO_MAGIC = 0x1A2B3C4D
    BT_SHB = 0x0A0D0D0A
    BT_IDB = 0x00000001
    BT_EPB = 0x00000006

    def __init__(self, path: str | Path, link_type: int = DLT_USER0,
                 snaplen: int = 65535) -> None:
        self.path = Path(path)
        self.link_type = link_type
        self.snaplen = snaplen
        self._fh: io.BufferedWriter | None = None

    def __enter__(self) -> PcapngWriter:
        self._fh = self.path.open("wb")
        self._write_shb()
        self._write_idb()
        return self

    def __exit__(self, *exc) -> None:
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    @staticmethod
    def _pad4(n: int) -> int:
        return (4 - n % 4) % 4

    def _write_block(self, block_type: int, body: bytes) -> None:
        assert self._fh is not None
        total_len = 12 + len(body)  # type(4) + len(4) + body + len(4)
        pad = self._pad4(len(body))
        total_len += pad
        self._fh.write(struct.pack("<II", block_type, total_len))
        self._fh.write(body)
        self._fh.write(b"\x00" * pad)
        self._fh.write(struct.pack("<I", total_len))

    def _write_shb(self) -> None:
        # byte_order_magic(4) maj(2) min(2) section_length(8) [opts]
        body = struct.pack(
            "<IHHq",
            self.PCAPNG_BO_MAGIC,
            1, 0,
            -1,
        )
        self._write_block(self.BT_SHB, body)

    def _write_idb(self) -> None:
        # link_type(2) reserved(2) snaplen(4)
        body = struct.pack("<HHI", self.link_type, 0, self.snaplen)
        self._write_block(self.BT_IDB, body)

    def write_packet(self, payload: bytes, timestamp_us: int | None = None) -> None:
        assert self._fh is not None
        if timestamp_us is None:
            import time
            timestamp_us = int(time.time() * 1_000_000)
        ts_high = (timestamp_us >> 32) & 0xFFFFFFFF
        ts_low = timestamp_us & 0xFFFFFFFF
        cap_len = len(payload)
        body = struct.pack("<IIIII", 0, ts_high, ts_low, cap_len, cap_len) + payload
        self._write_block(self.BT_EPB, body)

    def write_paging(self, pdu: bytes, timestamp_us: int | None = None) -> None:
        """Write a paging record. Prepends the 15-byte mac-lte pseudo-header
        so Wireshark dissects it in the LTE-RRC chain."""
        self.write_packet(PAGING_HEADER + pdu, timestamp_us)

    def write_sib1(self, pdu: bytes, timestamp_us: int | None = None) -> None:
        self.write_packet(SIB1_HEADER + pdu, timestamp_us)

    def write_sib2(self, pdu: bytes, timestamp_us: int | None = None) -> None:
        self.write_packet(SIB2_HEADER + pdu, timestamp_us)
