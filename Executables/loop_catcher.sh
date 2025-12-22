#!/bin/bash
#
# loop_catcher.sh - Continuous LTE signal capture script
#
# This script runs the pdsch_ue sniffer in a loop, switching between
# two LTE frequencies to capture paging requests.
#
# Compatible with srsRAN_4G (formerly srsLTE)
#

counter=0
frequencies=(1845000000 1815000000)

# Set paths - adjust these for your installation
SRSRAN_SNIFFER_DIR="${SRSRAN_SNIFFER_DIR:-/home/user/srsRAN-Sniffer/build}"
PDSCH_UE="${SRSRAN_SNIFFER_DIR}/bin/pdsch_ue"
CONVERT_CSV="${SRSRAN_SNIFFER_DIR}/bin/convert_to_csv"

# Verify executables exist
if [[ ! -x "$PDSCH_UE" ]]; then
    echo "Error: pdsch_ue not found at $PDSCH_UE"
    echo "Please set SRSRAN_SNIFFER_DIR environment variable"
    exit 1
fi

if [[ ! -x "$CONVERT_CSV" ]]; then
    echo "Warning: convert_to_csv not found at $CONVERT_CSV"
fi

function kill_pdsch_ue(){
  local timer=4m
  sleep ${timer}
  pkill pdsch_ue
}

echo "Starting srsRAN-Sniffer loop..."
echo "Frequencies: ${frequencies[*]}"
echo "Press Ctrl+C to stop"

while true; do
  ((counter++))
  current_freq=${frequencies[${counter}%2]}
  echo "$(date): Scanning frequency ${current_freq} Hz"

  kill_pdsch_ue &
  "$PDSCH_UE" -f ${current_freq} -r 0xfffe

  # Convert captured data to PCAP and CSV
  text2pcap imsi_pcap.txt imsi.pcap -l 147 2>/dev/null

  if [[ -x "$CONVERT_CSV" ]]; then
    "$CONVERT_CSV"
  fi
done
