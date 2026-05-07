#!/usr/bin/env bash
# Modernised replacement for the original Code/loop_catcher.sh.
#
# Differences:
#   * Uses the in-tree pdsch_sniffer (built via the project's own CMake) —
#     no rebuild of srsRAN_4G on every iteration.
#   * Writes pcapng directly via pdsch_sniffer; no text2pcap round-trip.
#   * Uses the Python analyzer to insert into a SQLite store after each
#     dwell, not a brittle shell+convert_to_csv pipeline.
#   * Refuses to run without --i-have-authorization passed through.
#
# Usage:
#   scripts/loop_catcher.sh \
#       --i-have-authorization \
#       --earfcns 1300,1600 \
#       --dwell 240 \
#       --out captures
set -euo pipefail

EARFCNS="1300,1600"  # band 3 — legacy 1815/1845 MHz
DWELL=240
OUT="captures"
AUTH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --earfcns) EARFCNS="$2"; shift 2 ;;
    --dwell) DWELL="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --i-have-authorization) AUTH=1; shift ;;
    -h|--help)
      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "$AUTH" ]]; then
  echo "Refusing — pass --i-have-authorization (see LEGAL.md)." >&2
  exit 2
fi

mkdir -p "$OUT"
DB="$OUT/captures.db"

IFS=',' read -r -a EARFCN_ARR <<< "$EARFCNS"

cycle=0
while true; do
  for earfcn in "${EARFCN_ARR[@]}"; do
    cycle=$((cycle + 1))
    pcap="$OUT/cycle-$cycle-earfcn-$earfcn.pcapng"
    journal="$OUT/cycle-$cycle-earfcn-$earfcn.journal"

    # Convert EARFCN → Hz via the Python helper (single source of truth).
    hz=$(python3 -c "
from srslte_sniffer.scanner import earfcn_to_hz
print(earfcn_to_hz($earfcn) or 0)
")
    if [[ "$hz" == "0" ]]; then
      echo "skipping unknown EARFCN $earfcn" >&2
      continue
    fi

    echo "[cycle $cycle] EARFCN $earfcn ($hz Hz) for ${DWELL}s"
    "$OUT/../build/src/pdsch_sniffer/pdsch_sniffer" \
        -f "$hz" \
        -t "$DWELL" \
        -j "$journal" \
        -p "$pcap" \
        --i-have-authorization || true

    # Run the analyzer over the journal — robust against mid-write crashes.
    if [[ -s "$journal" ]]; then
      srslte-sniffer journal-replay "$journal" --db "$DB" || true
    fi
  done
done
