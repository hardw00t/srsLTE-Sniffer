"""srsLTE-Sniffer v2 — modernised LTE/NR control-plane sniffer and analyzer.

This package provides:

* `decoder`        — ASN.1 RRC PCCH/SIB decoders (replaces hex pattern hacks).
* `pcap_io`        — readers/writers for the legacy text-pcap format and
                     proper pcapng with DLT 147 / GSMTAP framing.
* `analyzer`       — pipeline that turns raw payloads into structured records.
* `db`             — SQLite store for captures.
* `journal`        — append-only crash-safe capture journal.
* `scanner`        — EARFCN→cell-lock state machine.
* `dashboard`      — FastAPI/HTMX live UI.
* `tracker`        — TMSI-reassignment correlation.
* `rogue_detector` — defensive rogue-eNB anomaly detector.
* `nr_decoder`     — 5G NR research-mode skeleton.
* `cli`            — `srslte-sniffer` Click entrypoint.
"""

__version__ = "2.0.0"

LEGAL_BANNER = """
================================================================
 srsLTE-Sniffer v2 — capture mode
 Passive cellular interception is REGULATED OR ILLEGAL in most
 jurisdictions. By using --i-have-authorization you assert that
 you have written authorisation to operate on this RF channel.
 See LEGAL.md.
================================================================
""".strip()
