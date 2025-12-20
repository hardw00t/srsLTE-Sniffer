# Comprehensive TODO Implementation Plan

## Executive Summary

This document provides a detailed implementation plan for resolving all outstanding TODO items in the srsLTE-Sniffer project, an LTE IMSI catcher security research tool. The project is archived due to hardware access limitations, but this plan serves as complete documentation for future implementation.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [TODO Items Summary](#todo-items-summary)
3. [TODO Item 1: Output Data Handling](#todo-item-1-output-data-handling-enhancement)
4. [TODO Item 2: UDP Transmission Fix](#todo-item-2-fixme---udp-data-transmission-bug)
5. [TODO Item 3: SIB2 Capture](#todo-item-3-sib2-capture-implementation)
6. [TODO Item 4: CSV Converter Fixes](#todo-item-4-convert_to_csvc-issues)
7. [Implementation Sequencing](#implementation-sequencing-and-dependencies)

---

## Project Overview

**srsLTE-Sniffer** is an IMSI (International Mobile Subscriber Identity) catcher that leverages the srsLTE library to capture and analyze LTE downlink signals. The project targets paging requests in LTE networks to extract subscriber identifiers.

### Key Components

| File | Lines | Purpose |
|------|-------|---------|
| `Code/pdsch_ue.c` | 960 | Main IMSI catcher - decodes PDSCH for paging requests |
| `Code/cell_measurement.c` | 425 | SIB capture tool - needs SIB2 support |
| `Code/parse_data.c` | 168 | Payload parsing and file I/O functions |
| `Code/convert_to_csv.c` | 134 | Converts imsi.txt to CSV format |
| `Executables/loop_catcher.sh` | 21 | Orchestration script |

---

## TODO Items Summary

| # | Location | Type | Description | Severity |
|---|----------|------|-------------|----------|
| 1 | `pdsch_ue.c:299`, `cell_measurement.c:122` | TODO | Output data handling placeholder | Low |
| 2 | `pdsch_ue.c:755` | FIXME | UDP transmission broken for non-SF1 subframes | Medium |
| 3 | `README.md:73`, `README.md:395` | TODO | SIB2 capture incomplete | High |
| 4 | `convert_to_csv.c` (multiple) | BUG | S-TMSI parsing, memory leak, empty line crash | Medium |

---

## TODO Item 1: Output Data Handling Enhancement

### Location
- `Code/pdsch_ue.c:299`
- `Code/cell_measurement.c:122`

### Current Implementation
```c
/* TODO: Do something with the output data */
uint8_t *data[SRSLTE_MAX_CODEWORDS];
```

### Root Cause Analysis

The global array `data[SRSLTE_MAX_CODEWORDS]` stores decoded PDSCH data across multiple codewords (up to 2 for LTE). Currently:

1. **pdsch_ue.c**: Data is passed to `save_bytes()` at line 750 which writes to files, but there is no real-time processing, structured data extraction, or callback mechanism.

2. **cell_measurement.c**: Data is captured but only used for SIB1 extraction at line 348.

The TODO suggests implementing richer data handling such as:
- Real-time data stream processing
- Protocol decoding callbacks
- Database storage
- JSON/structured output

### Implementation Plan

#### Phase 1: Create Data Handler Infrastructure

**Step 1.1: Define Data Handler Callback Structure**

Create a new header file `data_handler.h`:
```c
// File: Code/data_handler.h
#ifndef DATA_HANDLER_H
#define DATA_HANDLER_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    DATA_TYPE_PAGING,
    DATA_TYPE_SIB1,
    DATA_TYPE_SIB2,
    DATA_TYPE_MIB,
    DATA_TYPE_UNKNOWN
} data_type_t;

typedef struct {
    data_type_t type;
    uint32_t sfn;           // System Frame Number
    uint32_t sfidx;         // Subframe index
    uint32_t rnti;          // Radio Network Temporary Identifier
    uint8_t *payload;       // Raw payload
    uint32_t payload_len;   // Payload length in bytes
    float rsrp;             // Reference Signal Received Power
    float snr;              // Signal-to-Noise Ratio
    uint64_t timestamp_us;  // Microsecond timestamp
} decoded_data_t;

typedef void (*data_callback_t)(const decoded_data_t *data, void *user_ctx);

// Register callback for specific data types
int register_data_handler(data_type_t type, data_callback_t cb, void *ctx);
void unregister_data_handler(data_type_t type);

// Process decoded data through registered handlers
void process_decoded_data(const decoded_data_t *data);

#endif
```

**Step 1.2: Implement Data Handler in `data_handler.c`**

```c
// File: Code/data_handler.c
#include "data_handler.h"

static const char *data_type_names[] = {
    "PAGING", "SIB1", "SIB2", "MIB", "UNKNOWN"
};

// Callback registry structure
static struct {
    data_callback_t callback;
    void *context;
} handlers[5] = {0};

int register_data_handler(data_type_t type, data_callback_t cb, void *ctx) {
    if (type < 0 || type > DATA_TYPE_UNKNOWN) return -1;
    handlers[type].callback = cb;
    handlers[type].context = ctx;
    return 0;
}

void unregister_data_handler(data_type_t type) {
    if (type >= 0 && type <= DATA_TYPE_UNKNOWN) {
        handlers[type].callback = NULL;
        handlers[type].context = NULL;
    }
}

void process_decoded_data(const decoded_data_t *data) {
    if (handlers[data->type].callback) {
        handlers[data->type].callback(data, handlers[data->type].context);
    }
    // Also call generic handler if registered
    if (handlers[DATA_TYPE_UNKNOWN].callback) {
        handlers[DATA_TYPE_UNKNOWN].callback(data, handlers[DATA_TYPE_UNKNOWN].context);
    }
}
```

#### Phase 2: Integrate into pdsch_ue.c

**Step 2.1: Replace raw data handling at line 750**

Current code:
```c
save_bytes(pcap_data, parse_file, "IMSI", data[0], n/4);
```

Replace with:
```c
// Build structured data object
decoded_data_t decoded = {
    .type = DATA_TYPE_PAGING,
    .sfn = sfn,
    .sfidx = sfidx,
    .rnti = prog_args.rnti,
    .payload = data[0],
    .payload_len = n/8,  // Convert bits to bytes
    .rsrp = rsrp0,
    .snr = 10 * log10(rsrp0 / noise)
};
struct timeval tv;
gettimeofday(&tv, NULL);
decoded.timestamp_us = tv.tv_sec * 1000000ULL + tv.tv_usec;

// Process through handler chain
process_decoded_data(&decoded);

// Backward compatibility: still save to files
save_bytes(pcap_data, parse_file, "IMSI", data[0], n/4);
```

#### Phase 3: Implement Example Handlers

**Step 3.1: JSON Output Handler**
```c
void json_output_handler(const decoded_data_t *data, void *ctx) {
    FILE *json_file = (FILE *)ctx;
    fprintf(json_file, "{\"type\":\"%s\",\"sfn\":%u,\"sfidx\":%u,"
            "\"rsrp\":%.2f,\"snr\":%.2f,\"payload\":\"",
            data_type_names[data->type], data->sfn, data->sfidx,
            data->rsrp, data->snr);
    for (uint32_t i = 0; i < data->payload_len; i++) {
        fprintf(json_file, "%02x", data->payload[i]);
    }
    fprintf(json_file, "\",\"timestamp\":%lu}\n", data->timestamp_us);
    fflush(json_file);
}
```

**Step 3.2: SQLite Database Handler (Optional)**
```c
#include <sqlite3.h>

void sqlite_handler(const decoded_data_t *data, void *ctx) {
    sqlite3 *db = (sqlite3 *)ctx;
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO captures (type, sfn, payload, rsrp, timestamp) "
                      "VALUES (?, ?, ?, ?, ?)";
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_int(stmt, 1, data->type);
    sqlite3_bind_int(stmt, 2, data->sfn);
    sqlite3_bind_blob(stmt, 3, data->payload, data->payload_len, SQLITE_STATIC);
    sqlite3_bind_double(stmt, 4, data->rsrp);
    sqlite3_bind_int64(stmt, 5, data->timestamp_us);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}
```

### Testing Approach

1. **Unit Tests**: Create test harness that simulates decoded data and verifies callback invocation
2. **Integration Tests**: Use recorded RF samples with known IMSI values
3. **Regression Tests**: Verify backward compatibility with existing file output

### Dependencies
- No external dependencies for base implementation
- Optional: SQLite3 for database handler
- Optional: libjansson for JSON output

---

## TODO Item 2: FIXME - UDP Data Transmission Bug

### Location
`Code/pdsch_ue.c:755-761`

### Current Implementation
```c
if (prog_args.net_port > 0) {
    if(sfidx == 1) {
        srslte_netsink_write(&net_sink, data[0], 1+(n-1)/8);
    } else {
    // FIXME: UDP Data transmission does not work
        for (uint32_t tb = 0; tb < SRSLTE_MAX_CODEWORDS; tb++) {
            if (ue_dl.pdsch_cfg.grant.tb_en[tb]) {
                srslte_netsink_write(&net_sink, data[tb], 1 + (ue_dl.pdsch_cfg.grant.mcs[tb].tbs - 1) / 8);
            }
        }
    }
}
```

### Root Cause Analysis

**Primary Issue**: The buffer size calculation differs between subframe 1 and other subframes:

| Subframe | Size Calculation | Source |
|----------|------------------|--------|
| sfidx == 1 | `1 + (n-1)/8` | Uses `n` from `srslte_ue_dl_decode()` return value (bits) |
| Other | `1 + (mcs[tb].tbs - 1) / 8` | Uses Transport Block Size from MCS table |

**Likely Root Causes**:

1. **Timing Issue**: Non-subframe-1 transmissions may occur before data is fully decoded
2. **Data Validity**: The `data[tb]` pointer may not be valid for all transport blocks
3. **Grant Configuration**: `ue_dl.pdsch_cfg.grant.tb_en[tb]` may be stale or incorrect
4. **Buffer Overrun**: The size calculation could exceed actual decoded data length

### Implementation Plan

#### Phase 1: Diagnostic Instrumentation

**Step 1.1: Add Debug Logging**

Before the FIXME block, add:
```c
if (prog_args.net_port > 0) {
    DEBUG("UDP TX: sfidx=%u, n=%d bits, tb_en=[%d,%d], tbs=[%d,%d]\n",
          sfidx, n,
          ue_dl.pdsch_cfg.grant.tb_en[0], ue_dl.pdsch_cfg.grant.tb_en[1],
          ue_dl.pdsch_cfg.grant.mcs[0].tbs, ue_dl.pdsch_cfg.grant.mcs[1].tbs);
}
```

**Step 1.2: Validate Data Before Transmission**

```c
// Add data validation
for (uint32_t tb = 0; tb < SRSLTE_MAX_CODEWORDS; tb++) {
    if (ue_dl.pdsch_cfg.grant.tb_en[tb]) {
        if (data[tb] == NULL) {
            ERROR("UDP TX: data[%d] is NULL\n", tb);
            continue;
        }

        uint32_t expected_bytes = 1 + (ue_dl.pdsch_cfg.grant.mcs[tb].tbs - 1) / 8;
        if (expected_bytes > 1500*8) {  // Max allocation size from line 379
            ERROR("UDP TX: Size %u exceeds buffer for tb=%d\n", expected_bytes, tb);
            continue;
        }

        srslte_netsink_write(&net_sink, data[tb], expected_bytes);
    }
}
```

#### Phase 2: Fix the Buffer Size Calculation

**Step 2.1: Unify Size Calculation**

The key insight is that `n` from `srslte_ue_dl_decode()` is the actual decoded payload size, while `tbs` is the theoretical maximum. Use `n` consistently:

```c
if (prog_args.net_port > 0) {
    // Use consistent size calculation for all subframes
    uint32_t tx_size = (n > 0) ? (1 + (n - 1) / 8) : 0;  // n is in bits

    if (n > 0 && tx_size <= 1500) {
        for (uint32_t tb = 0; tb < SRSLTE_MAX_CODEWORDS; tb++) {
            if (ue_dl.pdsch_cfg.grant.tb_en[tb] && data[tb] != NULL) {
                int sent = srslte_netsink_write(&net_sink, data[tb], tx_size);
                if (sent < 0) {
                    ERROR("UDP TX failed: tb=%d, size=%u, errno=%d\n",
                          tb, tx_size, errno);
                }
            }
        }
    }
}
```

#### Phase 3: Add Packet Framing for UDP

**Step 3.1: Create UDP Packet Header**

UDP is unreliable, so add framing for the receiver:

```c
typedef struct __attribute__((packed)) {
    uint32_t magic;         // 0x4C544553 "LTES"
    uint32_t sfn;           // System Frame Number
    uint8_t  sfidx;         // Subframe index
    uint8_t  tb_idx;        // Transport block index
    uint16_t payload_len;   // Payload length
    // payload follows
} udp_packet_header_t;

int send_udp_packet(srslte_netsink_t *sink, uint8_t *data, uint32_t len,
                    uint32_t sfn, uint8_t sfidx, uint8_t tb) {
    uint8_t packet[sizeof(udp_packet_header_t) + 1500];
    udp_packet_header_t *hdr = (udp_packet_header_t *)packet;

    hdr->magic = htonl(0x4C544553);
    hdr->sfn = htonl(sfn);
    hdr->sfidx = sfidx;
    hdr->tb_idx = tb;
    hdr->payload_len = htons(len);
    memcpy(packet + sizeof(udp_packet_header_t), data, len);

    return srslte_netsink_write(sink, packet,
                                sizeof(udp_packet_header_t) + len);
}
```

#### Phase 4: Socket Error Handling

**Step 4.1: Handle Non-Blocking Socket Errors**

```c
int ret = srslte_netsink_write(&net_sink, data[tb], tx_size);
if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Normal for non-blocking - buffer full, skip
        static uint32_t drop_count = 0;
        if (++drop_count % 1000 == 0) {
            WARN("UDP TX: %u packets dropped due to buffer full\n", drop_count);
        }
    } else {
        ERROR("UDP TX error: %s\n", strerror(errno));
    }
}
```

### Testing Approach

1. **Loopback Test**: Run with `-u 12345 -U 127.0.0.1` and capture with `nc -u -l 12345 | hexdump`
2. **Subframe Comparison**: Log packet counts per subframe to verify transmission across all subframes
3. **Wireshark Capture**: Capture UDP traffic and verify packet integrity
4. **Stress Test**: Run for extended periods to verify no memory leaks or crashes

### Dependencies
- None beyond existing srsLTE library

---

## TODO Item 3: SIB2 Capture Implementation

### Location
- `README.md:73` and `:395`
- `Code/cell_measurement.c:333-421`
- `Code/parse_data.c:89-91`

### Current Implementation

```c
// cell_measurement.c:333-351
case DECODE_SIB:
  /* We are looking for SI Blocks, search only in appropiate places */
  if ((srslte_ue_sync_get_sfidx(&ue_sync) == 5 && (sfn%2)==0)) {
    n = srslte_ue_dl_decode(&ue_dl, data, 0, sfn*10+srslte_ue_sync_get_sfidx(&ue_sync), acks);
    // ... only captures SIB1
```

### Root Cause Analysis

**LTE SI Message Scheduling (3GPP TS 36.331)**:

1. **SIB1**: Always transmitted in subframe 5 of even-numbered radio frames (SFN mod 2 = 0)
2. **SIB2-SIB13**: Scheduled dynamically according to `schedulingInfoList` in SIB1

**SIB1 Structure Contains**:
```asn1
SystemInformationBlockType1 ::= SEQUENCE {
    schedulingInfoList  SchedulingInfoList,
    ...
}
SchedulingInfoList ::= SEQUENCE (SIZE (1..maxSI-Message)) OF SchedulingInfo
SchedulingInfo ::= SEQUENCE {
    si-Periodicity     ENUMERATED {rf8, rf16, rf32, rf64, rf128, rf256, rf512},
    sib-MappingInfo    SIB-MappingInfo
}
```

**Why SIB2 is not being captured**:
1. Code only looks in subframe 5 of even frames (SIB1 location)
2. SIB2 is in a different SI message window scheduled by SIB1
3. Need to decode SIB1 first to determine SIB2 scheduling

### Implementation Plan

#### Phase 1: Parse SIB1 to Extract SI Scheduling

**Step 1.1: Create SIB1 Parser Structure**

Create `Code/sib_parser.h`:
```c
#ifndef SIB_PARSER_H
#define SIB_PARSER_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    SI_PERIODICITY_RF8 = 8,
    SI_PERIODICITY_RF16 = 16,
    SI_PERIODICITY_RF32 = 32,
    SI_PERIODICITY_RF64 = 64,
    SI_PERIODICITY_RF128 = 128,
    SI_PERIODICITY_RF256 = 256,
    SI_PERIODICITY_RF512 = 512
} si_periodicity_t;

typedef struct {
    si_periodicity_t periodicity;
    uint8_t sib_types[8];  // Which SIBs are in this SI message
    uint8_t num_sibs;
} scheduling_info_t;

typedef struct {
    uint8_t si_window_length;  // in ms (1,2,5,10,15,20,40)
    scheduling_info_t si_scheduling[32];
    uint8_t num_si_messages;
    bool sib2_found;
    uint8_t sib2_si_index;     // Which SI message contains SIB2
} sib1_info_t;

typedef struct {
    uint32_t start_sfn;
    uint8_t start_subframe;
    uint32_t end_sfn;
    uint8_t end_subframe;
} si_window_t;

// Parse SIB1 payload to extract scheduling info
int parse_sib1(uint8_t *payload, uint32_t len, sib1_info_t *info);

// Calculate next SI window for a given SI message
void calculate_si_window(const sib1_info_t *sib1, uint8_t si_index,
                         uint32_t current_sfn, si_window_t *window);

#endif
```

**Step 1.2: Implement SIB1 Parser**

Create `Code/sib_parser.c`:
```c
#include "sib_parser.h"
#include <string.h>

// Bit reader helper
typedef struct {
    uint8_t *data;
    uint32_t len;
    uint32_t bit_pos;
} bit_reader_t;

static void bit_reader_init(bit_reader_t *br, uint8_t *data, uint32_t len) {
    br->data = data;
    br->len = len;
    br->bit_pos = 0;
}

static uint32_t bit_reader_read(bit_reader_t *br, uint8_t num_bits) {
    uint32_t value = 0;
    for (int i = 0; i < num_bits; i++) {
        uint32_t byte_idx = br->bit_pos / 8;
        uint8_t bit_idx = 7 - (br->bit_pos % 8);
        if (byte_idx < br->len) {
            value = (value << 1) | ((br->data[byte_idx] >> bit_idx) & 1);
        }
        br->bit_pos++;
    }
    return value;
}

int parse_sib1(uint8_t *payload, uint32_t len, sib1_info_t *info) {
    bit_reader_t br;
    bit_reader_init(&br, payload, len);
    memset(info, 0, sizeof(sib1_info_t));

    // Note: This is a simplified parser. Full ASN.1 PER decoding
    // would require navigating through cellAccessRelatedInfo first.
    // The actual bit positions depend on optional fields.

    // Skip initial fields to reach schedulingInfoList
    // (Position depends on PLMN list size, TAC, CellIdentity, etc.)

    // For a typical SIB1, schedulingInfoList starts around bit 100-200
    // This needs calibration with actual captured data

    // SI-WindowLength (3 bits) - typically at known offset
    static const uint8_t si_window_map[] = {1, 2, 5, 10, 15, 20, 40, 80};

    // First SI message (index 0) always implicitly contains SIB2
    info->sib2_found = true;
    info->sib2_si_index = 0;
    info->si_scheduling[0].periodicity = SI_PERIODICITY_RF8;  // Default
    info->num_si_messages = 1;

    return 0;  // Return -1 on parse error
}

void calculate_si_window(const sib1_info_t *sib1, uint8_t si_index,
                         uint32_t current_sfn, si_window_t *window) {
    // Per 3GPP TS 36.331 Section 5.2.3:
    // SI message n is transmitted in radio frames satisfying:
    // SFN mod T = FLOOR(si_index * W / 10)
    // where T = si-Periodicity, W = si-WindowLength

    si_periodicity_t T = sib1->si_scheduling[si_index].periodicity;
    uint8_t W = sib1->si_window_length;
    if (W == 0) W = 5;  // Default window length
    if (T == 0) T = SI_PERIODICITY_RF8;  // Default periodicity

    // Find next valid starting frame
    uint32_t x = (si_index * W) / 10;
    uint32_t start_sfn = current_sfn - (current_sfn % T) + x;
    if (start_sfn <= current_sfn) {
        start_sfn += T;
    }

    window->start_sfn = start_sfn;
    window->start_subframe = 0;

    // Window ends after W subframes
    uint32_t total_subframes = start_sfn * 10 + W;
    window->end_sfn = total_subframes / 10;
    window->end_subframe = total_subframes % 10;
}
```

#### Phase 2: Modify cell_measurement.c State Machine

**Step 2.1: Update State Enum and Add Variables**

At line 140, change:
```c
// Before:
enum receiver_state { DECODE_MIB, DECODE_SIB, MEASURE} state;

// After:
enum receiver_state { DECODE_MIB, DECODE_SIB1, DECODE_SIB2, MEASURE } state;
```

Add after line 165:
```c
#include "sib_parser.h"

sib1_info_t sib1_info;
si_window_t sib2_window;
bool sib2_window_calculated = false;
```

**Step 2.2: Implement DECODE_SIB1 State (replace existing DECODE_SIB)**

```c
case DECODE_SIB1:
    if ((srslte_ue_sync_get_sfidx(&ue_sync) == 5 && (sfn%2)==0)) {
        n = srslte_ue_dl_decode(&ue_dl, data, 0,
                                sfn*10+srslte_ue_sync_get_sfidx(&ue_sync), acks);
        if (n < 0) {
            fprintf(stderr, "Error decoding UE DL\n");
            return -1;
        } else if (n > 0) {
            printf("Decoded SIB1. Payload (%d bits): ", n);
            srslte_vec_fprint_byte(stdout, data[0], n/8);
            save_bytes("database.txt", "sniffing_data.txt", "SIB1", data[0], n);

            // Parse SIB1 to get SIB2 scheduling
            if (parse_sib1(data[0], n/8, &sib1_info) == 0 && sib1_info.sib2_found) {
                printf("SIB2 scheduling found: SI message %d, periodicity=%d frames\n",
                       sib1_info.sib2_si_index,
                       sib1_info.si_scheduling[sib1_info.sib2_si_index].periodicity);
                calculate_si_window(&sib1_info, sib1_info.sib2_si_index,
                                    sfn, &sib2_window);
                sib2_window_calculated = true;
                printf("Next SIB2 window: SFN %u.%u to %u.%u\n",
                       sib2_window.start_sfn, sib2_window.start_subframe,
                       sib2_window.end_sfn, sib2_window.end_subframe);
                state = DECODE_SIB2;
            } else {
                printf("Could not parse SIB1 scheduling info, proceeding to MEASURE\n");
                state = MEASURE;
            }
        } else {
            printf("CFO: %+6.4f kHz, SFO: %+6.4f kHz, PDCCH-Det: %.3f\r",
                    srslte_ue_sync_get_cfo(&ue_sync)/1000,
                    srslte_ue_sync_get_sfo(&ue_sync)/1000,
                    (float) ue_dl.nof_detected/nof_trials);
            nof_trials++;
        }
    }
    break;
```

**Step 2.3: Add DECODE_SIB2 State**

```c
case DECODE_SIB2:
    {
        uint32_t current_sf = sfn * 10 + srslte_ue_sync_get_sfidx(&ue_sync);
        uint32_t window_start = sib2_window.start_sfn * 10 + sib2_window.start_subframe;
        uint32_t window_end = sib2_window.end_sfn * 10 + sib2_window.end_subframe;

        if (current_sf >= window_start && current_sf <= window_end) {
            // We're in the SIB2 SI window - try to decode
            n = srslte_ue_dl_decode(&ue_dl, data, 0, current_sf, acks);
            if (n > 0) {
                printf("\n*** Decoded SIB2! Payload (%d bits): ", n);
                srslte_vec_fprint_byte(stdout, data[0], n/8);
                save_bytes("database.txt", "sniffing_data.txt", "SIB2", data[0], n);
                state = MEASURE;
            }
        } else if (current_sf > window_end) {
            // Window passed without successful decode
            printf("\nSIB2 window [%u-%u] missed at sf=%u, calculating next window...\n",
                   window_start, window_end, current_sf);
            calculate_si_window(&sib1_info, sib1_info.sib2_si_index,
                               sfn, &sib2_window);
            printf("Next SIB2 window: SFN %u.%u to %u.%u\n",
                   sib2_window.start_sfn, sib2_window.start_subframe,
                   sib2_window.end_sfn, sib2_window.end_subframe);
        } else {
            // Waiting for window to start
            printf("Waiting for SIB2 window (current=%u, start=%u)\r",
                   current_sf, window_start);
        }
    }
    break;
```

#### Phase 3: Update parse_data.c

The SIB2 header is already defined in `parse_data.c:89-91`:
```c
if (strncmp(type, "SIB2", 5)==0){
    header = "0000 01 01 04 02 ff ff 03 00 00 04 0a 12 07 01 01 00 00";
}
```

This should work correctly when SIB2 payloads are passed to `save_bytes()`.

### Testing Approach

1. **Capture Known Cell**: Use a cell with known SIB2 configuration
2. **Wireshark Validation**: Decode captured SIB2 in Wireshark using filter `lte-rrc.sib2`
3. **Timing Verification**: Log SI window calculations vs actual decode times
4. **Edge Cases**: Test with different si-WindowLength and periodicity values

### Dependencies
- Understanding of 3GPP TS 36.331 SI scheduling
- ASN.1 PER decoding knowledge (for full SIB1 parsing)

---

## TODO Item 4: convert_to_csv.c Issues

### Location
`Code/convert_to_csv.c`

### Issues Identified

1. **S-TMSI After IMSI** (lines 110-113): Parsing fails when S-TMSI appears after IMSI
2. **Memory Leak** (lines 131-133): `free(line)` is commented out
3. **Empty Line Crash** (README note): Crashes on empty lines at file start

### Root Cause Analysis

**Issue 1: S-TMSI After IMSI**

Current logic at lines 106-117:
```c
if (imsi_index > 14 && index > 14 && counter != 1){
    print_s_tmsi(csv, payload, index-11, 10, s_tmsi_check, s_tmsi_checked);
    index -= 10;
    s_tmsi_check = false;
} /*else if (payload[imsi_length+index+2] != '0' && ... ) {
    // THIS IS COMMENTED OUT - handles S-TMSI after IMSI
}*/
```

**Issue 2: Memory Leak**

`getline()` allocates memory for `line`, but `free(line)` at lines 131-133 is commented out.

**Issue 3: Empty Line Crash**

When `imsi.txt` starts with empty lines:
- `strtok(read_line, ";")` returns NULL
- Code doesn't check for NULL before use

### Implementation Plan

#### Phase 1: Fix Empty Line Handling

**Step 1.1: Add Input Validation at Loop Start**

After line 40, add:
```c
while ((read = getline(&line, &len, fp)) != -1){
    // Skip empty lines and lines that are just whitespace
    if (read <= 1) continue;  // Empty or just newline

    // Trim trailing newline
    if (line[read-1] == '\n') {
        line[read-1] = '\0';
        read--;
    }

    // Verify line contains semicolon separator
    if (strchr(line, ';') == NULL) {
        fprintf(stderr, "Warning: Skipping malformed line: %s\n", line);
        continue;
    }

    // Rest of processing...
```

#### Phase 2: Fix S-TMSI After IMSI Parsing

**Step 2.1: Rewrite S-TMSI Detection Logic**

Replace the entire S-TMSI handling section (lines 98-123) with:

```c
// After printing IMSI fields, check for S-TMSI
bool found_before = false;
bool found_after = false;
char s_tmsi_before[11] = {0};
char s_tmsi_after[11] = {0};

// Check for S-TMSI BEFORE IMSI
// S-TMSI would be at position (imsi_index - 10 - separator)
if (imsi_index >= 11) {
    int potential_start = imsi_index - 11;

    // Verify it's a valid hex string (S-TMSI contains hex, IMSI is decimal only)
    bool valid_hex = true;
    bool has_hex_letter = false;
    for (int i = 0; i < 10 && potential_start + i < strlen(payload); i++) {
        char c = tolower(payload[potential_start + i]);
        if (!isxdigit(c)) {
            valid_hex = false;
            break;
        }
        if (c >= 'a' && c <= 'f') {
            has_hex_letter = true;
        }
    }
    // S-TMSI typically has some hex letters; pure digits might be part of IMSI
    if (valid_hex) {
        strncpy(s_tmsi_before, payload + potential_start, 10);
        s_tmsi_before[10] = '\0';
        found_before = true;
    }
}

// Check for S-TMSI AFTER IMSI
int after_pos = imsi_index + imsi_length;

// Skip the '8' terminator and any padding
while (after_pos < strlen(payload) &&
       (payload[after_pos] == '8' || payload[after_pos] == '0')) {
    after_pos++;
}

if (after_pos + 10 <= strlen(payload)) {
    bool valid_hex = true;
    for (int i = 0; i < 10; i++) {
        if (!isxdigit(payload[after_pos + i])) {
            valid_hex = false;
            break;
        }
    }
    if (valid_hex) {
        strncpy(s_tmsi_after, payload + after_pos, 10);
        s_tmsi_after[10] = '\0';
        found_after = true;
    }
}

// Output S-TMSI field
fprintf(csv, "\"");
if (found_before) {
    fprintf(csv, "%s", s_tmsi_before);
    if (found_after) fprintf(csv, ", ");
}
if (found_after) {
    fprintf(csv, "%s", s_tmsi_after);
}
fprintf(csv, "\"");
fprintf(csv, "\n");
```

#### Phase 3: Fix Memory Leak

**Step 3.1: Uncomment and Fix the free() Call**

At the end of main(), change:
```c
// Before (lines 129-134):
fclose(fp);
fclose(csv);
/*if (line){
    free(line);
}*/

// After:
fclose(fp);
fclose(csv);
if (line) {
    free(line);
    line = NULL;
}
return 0;
}
```

#### Phase 4: Add Robust Error Handling

**Step 4.1: Add File Open Validation**

At the beginning of main(), after variable declarations:
```c
fp = fopen("imsi.txt", "r");
if (fp == NULL) {
    fprintf(stderr, "Error: Cannot open imsi.txt: %s\n", strerror(errno));
    return 1;
}

csv = fopen("imsi.csv", "w");
if (csv == NULL) {
    fprintf(stderr, "Error: Cannot create imsi.csv: %s\n", strerror(errno));
    fclose(fp);
    return 1;
}
```

**Step 4.2: Add Bounds Checking Before Array Access**

Before accessing payload with calculated indices:
```c
if (imsi_index < 0 || imsi_index + imsi_length > strlen(payload)) {
    fprintf(stderr, "Warning: Invalid IMSI indices, skipping line\n");
    continue;
}
```

### Testing Approach

1. **Unit Tests**: Create test files with various S-TMSI/IMSI patterns:
   - IMSI only
   - S-TMSI before IMSI
   - S-TMSI after IMSI
   - S-TMSI before and after IMSI
   - Empty lines at start
   - Malformed lines

2. **Memory Testing**: Run with Valgrind:
   ```bash
   valgrind --leak-check=full ./convert_to_csv
   ```

3. **Regression Testing**: Compare output with known-good CSV files

### Dependencies
- None (standard C library only)
- Include `<errno.h>` for error handling

---

## Implementation Sequencing and Dependencies

```
                    ┌─────────────────────┐
                    │  1. Data Handler    │
                    │    Infrastructure   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              v                v                v
    ┌─────────────────┐ ┌─────────────┐ ┌───────────────┐
    │ 2. UDP Fix      │ │ 3. SIB2     │ │ 4. CSV Fix    │
    │ (uses handler   │ │   Capture   │ │ (independent) │
    │  optionally)    │ │             │ │               │
    └─────────────────┘ └─────────────┘ └───────────────┘
```

### Recommended Implementation Order

1. **convert_to_csv.c fixes** (Item 4) - No dependencies, quick win, ~2-4 hours
2. **UDP transmission fix** (Item 2) - Independent, enables real-time monitoring, ~4-6 hours
3. **Data handler infrastructure** (Item 1) - Foundation for extensibility, ~8-12 hours
4. **SIB2 capture** (Item 3) - Most complex, requires LTE spec knowledge, ~16-24 hours

### Estimated Effort Summary

| Item | Complexity | Estimated Hours | Risk Level |
|------|------------|-----------------|------------|
| 1. Data Handler | Medium | 8-12 hours | Low |
| 2. UDP Fix | Low-Medium | 4-6 hours | Medium |
| 3. SIB2 Capture | High | 16-24 hours | High |
| 4. CSV Fix | Low | 2-4 hours | Low |

**Total Estimated Effort**: 30-46 hours

---

## Critical Files Summary

| File | TODOs | Primary Changes Needed |
|------|-------|----------------------|
| `Code/pdsch_ue.c` | Line 299 (TODO), Lines 755-761 (FIXME) | Data handler integration, UDP fix |
| `Code/cell_measurement.c` | Line 122 (TODO) | SIB2 state machine, data handler |
| `Code/parse_data.c` | Lines 89-91 | Already has SIB2 header stub |
| `Code/convert_to_csv.c` | Lines 40, 106-117, 131-133 | Empty line, S-TMSI, memory leak fixes |
| `Code/data_handler.h` | NEW FILE | Callback infrastructure |
| `Code/data_handler.c` | NEW FILE | Handler implementation |
| `Code/sib_parser.h` | NEW FILE | SIB1 parsing structures |
| `Code/sib_parser.c` | NEW FILE | SIB1 parsing and SI window calculation |

---

## Appendix: LTE Background Information

### SI Message Scheduling (3GPP TS 36.331)

- **SIB1**: Fixed schedule - Subframe 5 of even-numbered radio frames
- **SIB2+**: Dynamic schedule defined by `schedulingInfoList` in SIB1
- **SI Window**: Time period during which an SI message may be transmitted
- **SI Periodicity**: How often an SI message is repeated (8-512 radio frames)

### IMSI/S-TMSI Structure

- **IMSI**: 15 decimal digits (MCC[3] + MNC[2-3] + MSIN[9-10])
- **S-TMSI**: 40 bits hex (MMEC[8 bits] + M-TMSI[32 bits])

### PCAP Headers for text2pcap

| Message Type | Header |
|--------------|--------|
| Paging | `0000 01 01 01 02 ff fe 03 00 00 04 00 00 07 01 01` |
| SIB1 | `0000 01 01 04 02 ff ff 03 00 00 04 09 05 07 01 01` |
| SIB2 | `0000 01 01 04 02 ff ff 03 00 00 04 0a 12 07 01 01 00 00` |

---

*Document generated for srsLTE-Sniffer project archival purposes.*
