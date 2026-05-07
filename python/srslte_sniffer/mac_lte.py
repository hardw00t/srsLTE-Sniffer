"""MAC-LTE pseudo-header decoder.

The 15-byte header srsLTE prepends to each PCCH/SIB dump (called the
"mac-lte-framed" format by Wireshark) carries useful metadata that the
v1 tooling threw away: RNTI, SFN, subframe number, RNTI type.

Format used by srsLTE — corresponds to the upstream Wireshark dissector
in `epan/dissectors/packet-mac-lte.c`. The header is a series of
*tagged TLV-like* fields:

  byte 0      : version magic (0x01)
  byte 1      : direction (0x01 = uplink, 0x00 = downlink — but srsLTE
                always emits 0x01 here, see parse_data.c)
  byte 2      : RNTI type   (0x01=P-RNTI, 0x04=SI-RNTI, others)
  byte 3      : 0x02         — separator
  bytes 4..5  : RNTI         (big-endian, e.g. ff fe = P-RNTI)
  byte 6      : 0x03
  bytes 7..8  : UE-ID / 0    (zeros for paging)
  byte 9      : 0x04
  byte 10     : SubChannel index / SI variant code
                (0x00=PCCH, 0x09=SIB1, 0x0A=SIB2 in the legacy headers)
  byte 11     : SubFrame number (0..9)
  byte 12     : 0x07
  byte 13..14 : Tag end (01 01)

There's natural variation across srsLTE versions, but the discriminator
positions match what `parse_data.c` writes. We only surface the fields
that are unambiguous.
"""

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class MacLteHeader:
    rnti_type: int
    rnti: int
    sub_variant: int  # the byte that distinguishes PCCH/SIB1/SIB2
    subframe: int

    @property
    def rnti_kind(self) -> str:
        # See 3GPP TS 36.321 §7.1
        if self.rnti_type == 0x01:
            return "p-rnti"
        if self.rnti_type == 0x04:
            return "si-rnti"
        return f"raw:{self.rnti_type:#04x}"

    @property
    def channel(self) -> str:
        if self.sub_variant == 0x00:
            return "pcch"
        if self.sub_variant == 0x09:
            return "sib1"
        if self.sub_variant == 0x0A:
            return "sib2"
        return f"raw:{self.sub_variant:#04x}"


def parse_mac_lte_header(buf: bytes) -> MacLteHeader | None:
    """Return a parsed header or None if the buffer doesn't look right.

    The header is exactly 15 bytes; callers that have a longer buffer
    should pass `buf[:15]`.
    """
    if len(buf) < 15:
        return None
    if buf[0] != 0x01:
        return None
    if buf[3] != 0x02 or buf[6] != 0x03 or buf[9] != 0x04 or buf[12] != 0x07:
        return None
    return MacLteHeader(
        rnti_type=buf[2],
        rnti=int.from_bytes(buf[4:6], "big"),
        sub_variant=buf[10],
        subframe=buf[11],
    )
