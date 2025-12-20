# srsLTE-Sniffer Enhancement Plan

## Overview

This document outlines future enhancements for the srsLTE-Sniffer project, building on the recently implemented TODO fixes and new features.

### Current State (Implemented)

| Component | Status | Description |
|-----------|--------|-------------|
| convert_to_csv.c | ✅ Complete | Fixed all bugs, added error handling |
| UDP Transmission | ✅ Complete | Packet framing with magic number |
| Data Handler | ✅ Complete | Extensible callback infrastructure |
| SIB Parser | ✅ Complete | SIB1/SIB2 parsing with SI windows |
| SIB2 Capture | ✅ Complete | State machine in cell_measurement.c |

---

## Priority HIGH: Critical Improvements

### 1. SQLite Database Handler

**Description**: Persistent storage for captured identities with queryable database.

**Implementation**:
```c
// Schema
CREATE TABLE captures (id, timestamp, type, sfn, rnti, payload_hex, cell_id, rsrp, snr);
CREATE TABLE identities (id, imsi, first_seen, last_seen, count, cells_seen);
CREATE TABLE stmsi_mappings (stmsi, imsi, timestamp, cell_id);
```

**Files to Create**:
- `Code/handler_sqlite.h`
- `Code/handler_sqlite.c`

**Complexity**: Medium (8-12 hours) | **Dependencies**: libsqlite3-dev

---

### 2. GUTI/TMSI Tracking Across Sessions

**Description**: Identity correlation to track S-TMSI assignments to IMSIs.

**Data Structure**:
```c
typedef struct {
    char imsi[16];
    char stmsi[11];
    uint64_t first_seen;
    uint64_t last_seen;
    uint16_t cell_ids[32];
    uint8_t num_cells;
    uint32_t paging_count;
} identity_record_t;
```

**Files to Create**:
- `Code/identity_tracker.h`
- `Code/identity_tracker.c`

**Complexity**: High (16-24 hours) | **Dependencies**: None

---

### 3. Multi-Frequency Scanning

**Description**: Automatic scanning across multiple frequencies with configurable dwell time.

**CLI Options**:
```
-F freq1,freq2,freq3    List of frequencies to scan
-D dwell_ms             Dwell time per frequency (default: 60000)
```

**Files to Modify**:
- `Code/pdsch_ue.c` - Add frequency hopping state machine

**Complexity**: High (20-30 hours) | **Dependencies**: Enhancement #1 recommended

---

### 4. Real-Time Web Dashboard

**Description**: Web-based visualization with live captures and statistics.

**Features**:
- Live capture feed via WebSocket
- Statistics charts (IMSIs/hour, signal quality)
- Cell information display
- Identity tracking visualization

**Files to Create**:
- `Code/web_server.h`
- `Code/web_server.c`
- `web/index.html`
- `web/dashboard.js`

**Complexity**: High (24-40 hours) | **Dependencies**: libmicrohttpd or mongoose

---

## Priority MEDIUM: Valuable Additions

### 5. Additional SIB Types (SIB3-SIB13)

**Description**: Extend SIB parser for cell reselection and inter-frequency information.

**SIB Types**:
| SIB | Content |
|-----|---------|
| SIB3 | Cell reselection serving frequency |
| SIB4 | Intra-frequency neighbor cells |
| SIB5 | Inter-frequency neighbor cells |
| SIB6 | UTRA neighbor cells |
| SIB7 | GERAN neighbor cells |
| SIB8 | CDMA2000 neighbor cells |

**Complexity**: High (24-32 hours) | **Dependencies**: 3GPP TS 36.331 knowledge

---

### 6. MQTT Message Handler

**Description**: Publish to MQTT broker for IoT/distributed processing integration.

**Topics**:
- `srsLTE/captures/paging` - Real-time paging captures
- `srsLTE/captures/sib` - SIB captures
- `srsLTE/stats` - Periodic statistics
- `srsLTE/identity/{imsi}` - Per-identity updates

**Complexity**: Medium (12-16 hours) | **Dependencies**: libpaho-mqtt3c

---

### 7. Configuration File Support

**Description**: YAML/JSON configuration for complex setups.

**Example Config**:
```yaml
radio:
  frequencies: [1845000000, 1815000000]
  gain: 40
capture:
  output_dir: "/var/log/srsLTE"
  formats: [json, sqlite, pcap]
tracking:
  enabled: true
  cache_size: 10000
web:
  enabled: true
  port: 8080
```

**Complexity**: Medium (8-12 hours) | **Dependencies**: libyaml or cjson

---

### 8. Cell Neighbor Detection

**Description**: Track neighboring cells from SIB4/SIB5 for mobility analysis.

**Data Structure**:
```c
typedef struct {
    uint16_t pci;           // Physical Cell ID
    uint32_t earfcn;        // Frequency
    int8_t q_offset;        // Cell-specific offset
    bool detected;          // Actively detected
    float rsrp;             // If detected
} neighbor_cell_t;
```

**Complexity**: High (20-28 hours) | **Dependencies**: Enhancement #5

---

### 9. Enhanced Logging with Rotation

**Description**: Production-ready logging with rotation and compression.

**Features**:
- Log levels: DEBUG, INFO, WARN, ERROR
- File rotation by size/time
- Optional gzip compression
- Syslog integration

**Complexity**: Medium (10-14 hours) | **Dependencies**: zlib (optional)

---

### 10. Kafka Streaming Handler

**Description**: Stream to Apache Kafka for big data pipelines.

**Topics**:
- `lte-captures` - All captures
- `lte-identities` - Identity events
- `lte-cells` - Cell information

**Complexity**: Medium (12-16 hours) | **Dependencies**: librdkafka

---

## Priority HIGH (Security Research)

### 11. Passive Location Tracking Analysis

**Description**: Timing-based location estimation using paging patterns.

**Features**:
- Timing Advance extraction
- Cell geometry database
- Multi-cell triangulation
- KML/GeoJSON export

**Complexity**: High (24-32 hours) | **Dependencies**: Enhancement #2

---

### 12. Traffic Pattern Analysis

**Description**: Analyze paging patterns for behavioral profiling.

**Metrics**:
```c
typedef struct {
    uint32_t paging_count_24h;
    float avg_interval_seconds;
    uint8_t hour_histogram[24];
    uint8_t day_histogram[7];
    bool is_stationary;
    float activity_score;
} behavior_profile_t;
```

**Complexity**: High (20-28 hours) | **Dependencies**: Enhancement #1, #2

---

### 13. Rogue eNB Configuration Export

**Description**: Export SIB configurations for base station research.

**Output**: srsLTE eNB configuration file format

**Complexity**: Medium (12-16 hours) | **Dependencies**: Enhancement #5

---

### 14. Identity Correlation Engine

**Description**: Build subscriber identity graphs from IMSI/S-TMSI/GUTI correlations.

**Data Structure**:
```c
typedef struct {
    char imsi[16];
    char guti[24];
    char stmsi_history[32][11];
    uint8_t stmsi_count;
    uint16_t mme_code;
    uint32_t m_tmsi_values[32];
} subscriber_graph_t;
```

**Complexity**: High (16-24 hours) | **Dependencies**: Enhancement #2

---

## Priority LOW: Nice-to-Have

### 15. Unit Testing Framework

**Description**: Unit tests using Unity framework.

**Test Files**:
- `tests/test_sib_parser.c`
- `tests/test_data_handler.c`
- `tests/test_convert_csv.c`
- `tests/test_bit_reader.c`

**Complexity**: Medium (12-16 hours)

---

### 16. Wireshark Plugin

**Description**: Lua dissector for UDP framed packets.

**File**: `wireshark/srslte_sniffer.lua`

**Complexity**: Low (6-8 hours)

---

### 17. Enhanced PCAP Export

**Description**: Direct PCAP writing with proper GSMTAP encapsulation.

**Features**:
- Complete GSMTAP headers
- pcapng format with timestamps
- No text2pcap dependency

**Complexity**: Medium (8-12 hours)

---

### 18. Build System Modernization

**Description**: CMake build with feature flags.

**Files**:
- `CMakeLists.txt`
- `Dockerfile`
- `docker-compose.yml`

**Complexity**: Medium (10-14 hours)

---

### 19. Memory Pool Allocator

**Description**: Fixed-size block allocator for high-throughput.

**Pools**:
- decoded_data_t structures
- Payload buffers (1500 bytes)
- Identity records

**Complexity**: Medium (8-12 hours)

---

### 20. Multi-Threading for Handlers

**Description**: Offload handler processing to worker threads.

**Features**:
- Lock-free ring buffer
- Handler worker thread
- Flow control for backpressure
- Graceful shutdown

**Complexity**: High (16-20 hours)

---

## Implementation Dependency Graph

```
                      Build System (#18)
                            │
         ┌──────────────────┼──────────────────┐
         v                  v                  v
    SQLite (#1)      Config File (#7)    Unit Tests (#15)
         │
         v
    GUTI Tracking (#2) ◄─── Logging (#9)
         │
    ┌────┴────────────────────────────────┐
    v                                      v
Location Analysis (#11)              SIB3-13 (#5)
    │                                      │
    v                                      v
Pattern Analysis (#12)              Neighbors (#8)
    │                                      │
    └──────────────┬───────────────────────┘
                   v
         Identity Correlation (#14)

Independent:
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ Multi-Freq  │ │    MQTT     │ │   Kafka     │
│    (#3)     │ │    (#6)     │ │   (#10)     │
└─────────────┘ └─────────────┘ └─────────────┘
```

---

## Recommended Implementation Order

### Phase 1: Foundation (Week 1-2)
1. Build System Modernization (#18)
2. Enhanced Logging (#9)
3. Unit Testing Framework (#15)

### Phase 2: Core Features (Week 3-5)
1. SQLite Database Handler (#1)
2. GUTI/TMSI Tracking (#2)
3. Configuration File Support (#7)

### Phase 3: Analysis Capabilities (Week 6-8)
1. Additional SIB Types (#5)
2. Cell Neighbor Detection (#8)
3. Passive Location Analysis (#11)

### Phase 4: Integration (Week 9-10)
1. Real-Time Web Dashboard (#4)
2. Enhanced PCAP Export (#17)
3. MQTT Handler (#6)

### Phase 5: Advanced Features (Week 11-12)
1. Traffic Pattern Analysis (#12)
2. Identity Correlation Engine (#14)
3. Multi-Frequency Scanning (#3)

### Phase 6: Performance & Polish (Week 13-14)
1. Memory Pool Allocator (#19)
2. Multi-Threading (#20)
3. Wireshark Plugin (#16)

---

## Effort Estimates Summary

| Priority | Enhancements | Estimated Hours |
|----------|-------------|-----------------|
| HIGH (Critical) | #1, #2, #3, #4 | 64-106 |
| MEDIUM (Valuable) | #5, #6, #7, #8, #9, #10 | 86-118 |
| HIGH (Security Research) | #11, #12, #13, #14 | 72-100 |
| LOW (Nice-to-Have) | #15, #16, #17, #18, #19, #20 | 60-82 |

**Total Estimated Effort**: 282-406 hours (7-10 developer weeks)

---

*Document generated for srsLTE-Sniffer project planning.*
