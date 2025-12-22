# srsRAN-Sniffer (formerly srsLTE-Sniffer)

LTE IMSI Catcher and Signal Analyzer - A security research tool for capturing and analyzing LTE downlink signals.

> **Note**: This project is for authorized security research, educational purposes, and CTF challenges only.

## Project Status

This project has been significantly enhanced with:
- Full **srsRAN_4G** compatibility (migrated from legacy srsLTE)
- Comprehensive **MIB, SIB1, SIB2, and Paging parsers**
- **Identity tracking** with IMSI/S-TMSI correlation
- **Data handler infrastructure** for extensible processing
- **SQLite database** support for persistent storage
- **JSON configuration** system
- **Wireshark dissector** for real-time analysis
- **119 unit tests** with full coverage

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Running](#running)
- [Architecture](#architecture)
- [What It Captures](#what-it-captures)
- [Tools](#tools)
- [Configuration](#configuration)
- [Wireshark Integration](#wireshark-integration)
- [Testing](#testing)
- [API Reference](#api-reference)
- [References](#references)

---

## Features

### Core Capabilities
- **Cell Search**: Automatic LTE cell detection using PSS/SSS synchronization
- **MIB Decoding**: Master Information Block parsing with bandwidth, PHICH config, SFN
- **SIB Decoding**: System Information Block 1 & 2 with PLMN, cell selection, SI scheduling
- **Paging Capture**: Real-time paging request interception with IMSI/S-TMSI extraction
- **Identity Tracking**: Correlate S-TMSI to IMSI across sessions

### New Enhancements
| Feature | Description |
|---------|-------------|
| **MIB Parser** | Full MIB decoding with JSON export |
| **SIB Parser** | SIB1/SIB2 parsing with SI window calculation |
| **Paging Parser** | Heuristic IMSI/S-TMSI detection |
| **Identity Tracker** | Cross-session identity correlation |
| **Data Handler** | Callback-based extensible processing |
| **Memory Pool** | Efficient memory management |
| **Config Parser** | JSON configuration support |
| **Logger** | Multi-level logging with file output |
| **SQLite Handler** | Persistent database storage |
| **PCAP Writer** | Direct PCAP file generation |

---

## Prerequisites

### Required
- CMake 3.10+
- GCC/Clang with C11 support
- SQLite3 development libraries
- [text2pcap](https://www.wireshark.org/docs/man-pages/text2pcap.html) (for PCAP conversion)

### For SDR Capture (Optional)
- [srsRAN_4G](https://github.com/srsran/srsRAN_4G) (version 23.04+)
- FFTW3, MbedTLS, libconfig
- SDR hardware (USRP, BladeRF, LimeSDR, etc.)

### Install Dependencies (Ubuntu/Debian)
```bash
# Core dependencies
sudo apt-get install cmake build-essential libsqlite3-dev

# For SDR capture (optional)
sudo apt-get install libfftw3-dev libmbedtls-dev libsctp-dev libconfig++-dev
```

---

## Building

### Standalone Tools (No SDR)
Build the core library, parsers, and tools without SDR support:

```bash
mkdir build && cd build
cmake .. -DBUILD_TESTS=ON -DBUILD_TOOLS=ON
make -j$(nproc)

# Run tests
./bin/run_tests
```

### With srsRAN_4G (Full SDR Support)
Build with full SDR capture capabilities:

```bash
# First, build and install srsRAN_4G
git clone https://github.com/srsran/srsRAN_4G.git
cd srsRAN_4G && mkdir build && cd build
cmake .. && make -j$(nproc) && sudo make install

# Then build srsRAN-Sniffer
cd /path/to/srsRAN-Sniffer
mkdir build && cd build
cmake .. -DBUILD_SNIFFER=ON -DBUILD_TESTS=ON
make -j$(nproc)
```

### Build Options
| Option | Default | Description |
|--------|---------|-------------|
| `BUILD_TESTS` | OFF | Build unit tests |
| `BUILD_TOOLS` | ON | Build standalone tools |
| `BUILD_SNIFFER` | OFF | Build SDR sniffer (requires srsRAN_4G) |

---

## Running

### Continuous Capture
```bash
# Set environment variable for build location
export SRSRAN_SNIFFER_DIR=/path/to/srsRAN-Sniffer/build

# Run continuous capture loop
./Executables/loop_catcher.sh
```

### Manual Capture
```bash
# Cell measurement and SIB capture
./bin/cell_measurement -f 1845000000 -g 40

# PDSCH/Paging capture
./bin/pdsch_ue -f 1845000000 -r 0xfffe
```

### Command Line Options
```
pdsch_ue options:
  -f  Frequency in Hz (required)
  -r  RNTI in hex (default: 0xfffe for SI-RNTI)
  -a  RF args (SDR device selection)
  -g  RX gain in dB (default: AGC)
  -n  Number of subframes to capture
  -u  UDP port for streaming
  -v  Verbose output
```

### Finding Your LTE Frequency
- **Samsung**: Dial `*#0011#`
- **iPhone**: Dial `*3001#12345#*` and press call
- Convert EARFCN to frequency: http://niviuk.free.fr/lte_band.php

---

## Architecture

```
srsRAN-Sniffer/
├── Code/
│   ├── pdsch_ue.c          # Main PDSCH/Paging sniffer
│   ├── cell_measurement.c  # Cell search and SIB capture
│   ├── mib_parser.c        # MIB decoder
│   ├── sib_parser.c        # SIB1/SIB2 decoder
│   ├── paging_parser.c     # Paging message parser
│   ├── identity_tracker.c  # IMSI/S-TMSI correlation
│   ├── data_handler.c      # Extensible callback system
│   ├── handler_identity.c  # Identity extraction handler
│   ├── handler_sqlite.c    # SQLite storage handler
│   ├── config_parser.c     # JSON configuration
│   ├── logger.c            # Logging system
│   ├── memory_pool.c       # Memory management
│   ├── pcap_writer.c       # PCAP file generation
│   ├── parse_data.c        # Legacy payload processing
│   └── convert_to_csv.c    # CSV export tool
├── tests/                  # Unit tests (119 tests)
├── wireshark/              # Wireshark dissectors
├── cmake/                  # CMake configuration
└── Executables/            # Shell scripts
```

### Data Flow
```
SDR → srsRAN_4G PHY → pdsch_ue → Data Handler → [Handlers]
                                      ↓
                    ┌─────────────────┼─────────────────┐
                    ↓                 ↓                 ↓
              JSON Logger      SQLite Handler    Identity Tracker
                    ↓                 ↓                 ↓
              capture.jsonl     sniffer.db      IMSI/S-TMSI DB
```

---

## What It Captures

### Master Information Block (MIB)
- System bandwidth (1.4 - 20 MHz)
- PHICH configuration (duration, Ng)
- System Frame Number (SFN)
- Number of antenna ports

### System Information Block 1 (SIB1)
- PLMN Identity (MCC/MNC)
- Tracking Area Code (TAC)
- Cell ID
- Cell barred status
- SI scheduling information

### System Information Block 2 (SIB2)
- Access barring configuration
- RACH configuration
- BCCH/PCCH configuration
- UE timers and constants

### Paging Messages
- **IMSI** (15 digits): MCC + MNC + MSIN
- **S-TMSI** (40 bits): MMEC + M-TMSI
- Paging cause and CN domain

---

## Tools

### pdsch_ue
Main IMSI catcher - captures paging requests from PDSCH.

```bash
./bin/pdsch_ue -f 1845000000 -r 0xfffe
```

Output files:
- `imsi_pcap.txt` - Raw payloads for text2pcap
- `imsi.txt` - Filtered IMSI captures
- `capture.jsonl` - JSON log of all captures

### cell_measurement
Cell search and SIB capture with signal measurements.

```bash
./bin/cell_measurement -f 1845000000
```

Output:
- Cell ID, bandwidth, antenna ports
- RSRP, RSRQ, SNR measurements
- SIB1/SIB2 decoded content

### convert_to_csv
Convert captured data to CSV format.

```bash
./bin/convert_to_csv
```

Output: `imsi.csv` with columns:
- Timestamp, IMSI, MCC, MNC, MSIN, S-TMSI

---

## Configuration

Create `config.json` for custom settings:

```json
{
  "capture": {
    "frequency": 1845000000,
    "gain": 40,
    "rnti": "0xfffe"
  },
  "output": {
    "pcap_file": "capture.pcap",
    "json_file": "capture.jsonl",
    "sqlite_db": "sniffer.db"
  },
  "logging": {
    "level": "info",
    "file": "sniffer.log"
  },
  "identity": {
    "track_stmsi": true,
    "correlation_timeout": 3600
  }
}
```

---

## Wireshark Integration

### Install Dissector
Copy the Lua dissector to Wireshark plugins:

```bash
# Linux
cp wireshark/srsran_sniffer.lua ~/.local/lib/wireshark/plugins/

# macOS
cp wireshark/srsran_sniffer.lua ~/.config/wireshark/plugins/

# Windows
copy wireshark\srsran_sniffer.lua %APPDATA%\Wireshark\plugins\
```

### Convert to PCAP
```bash
text2pcap imsi_pcap.txt imsi.pcap -l 147
wireshark imsi.pcap
```

### Useful Wireshark Filters
```
# Packets with IMSI
lte-rrc.ue_Identity == 1

# Only S-TMSI
lte-rrc.ue_Identity == 0

# srsRAN protocol
srsran

# Filter by IMSI
srsran.imsi contains "52501"
```

### UDP Streaming
Enable real-time streaming to Wireshark:

```bash
./bin/pdsch_ue -f 1845000000 -u 5000
```

Then in Wireshark: Capture → Options → UDP port 5000

---

## Testing

Run the full test suite:

```bash
cd build
./bin/run_tests
```

Test coverage includes:
- MIB Parser (13 tests)
- SIB Parser (8 tests)
- Paging Parser (18 tests)
- Identity Tracker (14 tests)
- Data Handler (11 tests)
- Memory Pool (10 tests)
- Config Parser (13 tests)
- Logger (10 tests)
- Bit Reader (9 tests)
- CSV Conversion (13 tests)

---

## API Reference

### MIB Parser
```c
#include "mib_parser.h"

mib_info_t mib;
if (mib_parse(bch_payload, 3, &mib) == 0) {
    printf("Bandwidth: %s\n", mib_bandwidth_str(mib.dl_bandwidth));
    printf("SFN: %d\n", mib.sfn);
}
```

### Paging Parser
```c
#include "paging_parser.h"

paging_message_t msg;
if (paging_parse(data, len, &msg) == 0) {
    for (int i = 0; i < msg.num_records; i++) {
        if (msg.records[i].id_type == PAGING_ID_IMSI) {
            printf("IMSI: %s\n", msg.records[i].imsi.digits);
        }
    }
}
```

### Data Handler
```c
#include "data_handler.h"

void my_handler(const decoded_data_t *data, void *ctx) {
    printf("Captured: type=%d, len=%d\n", data->type, data->payload_len);
}

data_handler_init();
data_handler_register(DATA_TYPE_PAGING, my_handler, NULL, "My Handler");
// ... capture loop ...
data_handler_shutdown();
```

### Identity Tracker
```c
#include "identity_tracker.h"

identity_tracker_t *tracker = identity_tracker_create(1000);
identity_tracker_record_imsi(tracker, &imsi, cell_id, timestamp);
identity_tracker_correlate(tracker, &stmsi, &imsi, cell_id, timestamp);

// Later: find IMSI by S-TMSI
imsi_t found;
if (identity_tracker_stmsi_to_imsi(tracker, &stmsi, &found)) {
    printf("Found IMSI: %s\n", found.digits);
}
```

---

## Signal Quality Guide

When capturing, monitor the constellation plots:

| Plot | Good Signal | Bad Signal |
|------|-------------|------------|
| **PDSCH Equalized** | 4 clear dots (QPSK) | Scattered/fuzzy |
| **PDCCH Equalized** | 5 distinguishable dots | Concentrated center |
| **Channel Response** | Smooth curve | Erratic/spiky |
| **PSS Cross-Corr** | Clear peak | No distinct peak |

If signal is poor:
1. Check antenna connection
2. Adjust gain (`-g` option)
3. Verify frequency is correct
4. Move closer to cell tower

---

## References

### Papers
1. [4G/LTE IMSI Catchers for Non-Programmers](https://arxiv.org/pdf/1702.04434.pdf)
2. [LTE Security, Protocol Exploitation and Location Tracking](https://arxiv.org/pdf/1607.05171.pdf)
3. [Practical Attacks Against Privacy in 4G/LTE](https://arxiv.org/pdf/1510.07563.pdf)

### Tools & Resources
- [srsRAN_4G](https://github.com/srsran/srsRAN_4G) - Open source 4G/LTE library
- [EARFCN Calculator](http://niviuk.free.fr/lte_band.php) - Convert EARFCN to frequency
- [LTE Encyclopedia](https://sites.google.com/site/lteencyclopedia/) - LTE acronyms reference

---

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).

Based on srsRAN_4G by Software Radio Systems Limited.

---

## Disclaimer

This tool is provided for authorized security research, educational purposes, and CTF challenges only. Users are responsible for ensuring compliance with all applicable laws and regulations. Unauthorized interception of communications is illegal in most jurisdictions.
