# Usage

## Install (analyzer side, no SDR needed)

```bash
pip install -e .
srslte-sniffer --help
```

## Decode a capture file

The fastest way to validate that everything works against your own data:

```bash
srslte-sniffer analyze "Output Files/imsi.pcap" --db captures.db
# {
#   "frames": 251583,
#   "decoded_pcch": 251532,
#   "pagings_total": 312292,
#   ...
# }
```

By default IMSI / M-TMSI values are **SHA-256 hashed** in the DB. Pass
`--unsafe-raw` to keep the raw values — only do this if you have lawful
authorisation, see [LEGAL.md](../LEGAL.md).

## Decode a single PDU

```bash
srslte-sniffer decode 40016c445a8200dabf6960450000
# {"ok": true, "records": [{"kind": "s-tmsi", "mmec": 22, "m_tmsi": 3292899360, ...}]}
```

## Live dashboard

```bash
srslte-sniffer dashboard --db captures.db --port 8000
# open http://127.0.0.1:8000
```

## TMSI tracker

```bash
srslte-sniffer track --db captures.db --window-ms 200
```

## Rogue-eNB detection

```bash
srslte-sniffer detect --db captures.db --allowed-plmns "525-01,525-02,525-05"
```

## Replay a journal after a crash

```bash
srslte-sniffer journal-replay captures/cycle-12.journal --db captures.db
```

## Capture (requires srsRAN_4G + SDR)

```bash
cmake -S . -B build && cmake --build build -j
./build/src/pdsch_sniffer/pdsch_sniffer \
    -f 1845000000 -t 240 \
    -j caps.journal -p caps.pcapng \
    --i-have-authorization
```

Or sweep with the CLI:

```bash
srslte-sniffer scan \
    --earfcns 1300,1600 \
    --dwell 240 \
    --cycles 100 \
    --i-have-authorization
```

## Docker

```bash
docker compose up dashboard
# analyzer image:
docker run --rm -v "$PWD/captures:/captures" srslte-sniffer:python \
    srslte-sniffer analyze /captures/in.pcapng --db /captures/captures.db
```
