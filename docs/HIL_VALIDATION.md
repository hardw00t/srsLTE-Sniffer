# HIL bring-up runbook

The C sniffer (`src/pdsch_sniffer/sniffer.c`) targets srsRAN_4G master and
has been API-cross-checked against:

- `lib/include/srsran/phy/ue/ue_sync.h`
- `lib/include/srsran/phy/ue/ue_dl.h`
- `lib/examples/pdsch_ue.c` (reference example)

This runbook is what to do when actually exercising the binary against
real RF (or the docker-compose lab in `tests/hil/`).

## Step 0 — Prerequisites

- Linux host (Ubuntu 22.04 tested).
- Docker + Docker Compose v2.
- Hardware: USRP B210/X310 *or* the docker-compose ZMQ virtual-radio
  setup (no real RF needed, but the test SIM and key need to match
  `tests/hil/docker-compose.yml`).

## Step 1 — Build the `full` image

```bash
docker compose -f tests/hil/docker-compose.yml build
```

Expected: the build completes with the embedded srsRAN_4G install at
`/opt/srsRAN_4G` and the sniffer binaries at `/usr/local/bin`.

## Step 2 — Smoke-test the `--dry-run` path

This step doesn't need the lab stack — it's the quickest way to confirm
the binary's I/O paths work in CI before any RF is involved.

```bash
docker run --rm -v "$PWD/captures:/captures" srslte-sniffer:full \
    pdsch_sniffer --dry-run --dry-run-count 100 \
    -j /captures/dry.journal -p /captures/dry.pcapng

docker run --rm -v "$PWD/captures:/captures" srslte-sniffer:full \
    srslte-sniffer analyze /captures/dry.pcapng --db /captures/dry.db
```

Expected output: `pagings_total: 100`, `failed: 0`. If you see decode
failures, the journal/pcapng format has drifted — check that
`PAGING_HEADER` constants in C and Python are byte-identical.

## Step 3 — Bring up the lab stack

```bash
RUN_HIL=1 \
    docker compose -f tests/hil/docker-compose.yml \
    up --abort-on-container-exit --exit-code-from sniffer
```

The `enb` and `ue` containers wire up over ZMQ; the `sniffer` container
captures the resulting paging traffic, runs the analyzer, and writes
`captures/track.json`.

Expected: `track.json` contains an entry for IMSI `001010123456789`
(matching `usim.imsi=` in the compose file). If you see "no cell found",
check that the eNB came up before the sniffer (the compose adds a
`sleep 10` for that — increase if needed).

## Step 4 — Real RF

Once the docker path is green:

```bash
docker run --rm --net=host --privileged \
    -v /dev/bus/usb:/dev/bus/usb \
    -v "$PWD/captures:/captures" \
    srslte-sniffer:full \
    pdsch_sniffer \
        -f 1845000000 -g 70 \
        -j /captures/real.journal -p /captures/real.pcapng \
        -t 60 \
        --i-have-authorization
```

> Real RF capture is regulated or illegal in most jurisdictions. Do
> this only inside a Faraday cage, against your own private eNB, or
> with documented lawful authorisation. See [LEGAL.md](../LEGAL.md).

## Known pitfalls

| Symptom | Likely cause |
|---|---|
| `srsran_rf_open_devname` returns non-zero | UHD/USRP udev rules missing; run `uhd_find_devices` first. |
| Cell search hangs | Wrong centre frequency; verify with `*#0011#` (Samsung) / `*3001#12345#*` (iPhone). |
| `srsran_ue_dl_find_and_decode` returns 0 forever | RNTI mismatch — confirm `pdsch_cfg.rnti = 0xFFFE` for paging. |
| Many PER decode failures downstream | RF SNR low; raise `-g`, check antenna placement. |
| API symbol unresolved at link time | srsRAN_4G master changed since this branch was written. Re-cross-check `ue_dl.h` / `ue_sync.h` and update `sniffer.c`. |

## Reproducing the demo capture

The repo ships `imsi_pcap_demo.{txt,pcap}` (≈250k frames). To reproduce
the analysis without any RF:

```bash
srslte-sniffer analyze "Output Files/imsi.pcap" --db demo.db
srslte-sniffer track --db demo.db | head
srslte-sniffer detect --db demo.db
```

Expected: ~312k paging records, 51,400 multi-record frames, 117 IMSIs,
51 PER-decode failures (the natural OTA bit-error rate).

## When the API drifts

If `cmake --build` errors on undeclared symbols after a srsRAN_4G bump:

1. Open the failing line in `sniffer.c` (or `cell_measurement.c`).
2. Find the matching symbol in upstream's `lib/include/srsran/phy/`.
3. Update the call site; mention the upstream commit SHA in the diff.
4. Re-run the dry-run smoke test (Step 2). If it passes, the I/O
   half is intact and only the API surface changed.

The sniffer binary is intentionally thin precisely because the
analytical work is in Python — keep `sniffer.c` mechanical and
mirror upstream rather than rolling new logic.
