#!/usr/bin/env bash
# dwell.sh — invoked by `srslte-sniffer scan` for each EARFCN in the plan.
# Args: EARFCN HZ DWELL_SECONDS
set -euo pipefail
EARFCN="${1:?earfcn}"
HZ="${2:?hz}"
DWELL="${3:?dwell}"

OUT="${OUT:-captures}"
mkdir -p "$OUT"

PCAP="$OUT/scan-$EARFCN.pcapng"
JOURNAL="$OUT/scan-$EARFCN.journal"

# Path to the built pdsch_sniffer; override with $SNIFFER_BIN.
SNIFFER_BIN="${SNIFFER_BIN:-./build/src/pdsch_sniffer/pdsch_sniffer}"

"$SNIFFER_BIN" -f "$HZ" -t "$DWELL" \
    -j "$JOURNAL" -p "$PCAP" \
    --i-have-authorization
