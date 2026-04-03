# flowsense — Design Specification

**Passive DPI interference detector for Linux L2 bridges.**

Listens on a network interface via AF_PACKET (read-only, zero impact on traffic), tracks TCP/UDP flows, and reports
evidence of DPI interference — RST injection, silent drops, throttling, TCP window manipulation, and more.

Think `tcpdump`, but instead of showing packets, it shows **what your ISP is doing to your traffic**.

```bash
$ flowsense -i br-lan
[14:23:01] 100.21.56.3:443    RST_INJECTION       ttl=52→61 salvo=3 after_hello=12ms
[14:23:05] 194.10.20.30:443   THROTTLE_CLIFF      bytes=16384 stall=3.2s
[14:23:12] 123.45.67.89:443   SILENT_DROP          retransmits=5 post_hello
[14:23:30] 88.12.44.5:443     ACK_DROP             asymmetric=true server_retransmits=8
```

**Not a DPI engine. Not an IDS. A DPI witness.**

---

## Architecture

```
┌─────────────────────────────────────────────┐
│                  flowsense                  │
│                                             │
│  ┌──────────┐     ┌────────────┐            │
│  │ Capture  │───▶ │ Parser     │            │
│  │ AF_PACKET│     │ ETH/IP/TCP │            │
│  │ MMAP ring│     └─────┬──────┘            │
│  └──────────┘          │                    │
│                   ┌─────▼──────┐            │
│                   │ Flow Table │            │
│                   │ (dst_ip,   │            │
│                   │  dst_port) │            │
│                   └─────┬──────┘            │
│                         │                   │
│          ┌──────────────┼──────────────┐    │
│          ▼              ▼              ▼    │
│  ┌──────────┐   ┌────────────┐  ┌─────────┐ │
│  │ Injection│   │ Drop       │  │Throughput││
│  │ Detector │   │ Detector   │  │Detector │ │
│  └─────┬────┘   └─────┬──────┘  └────┬────┘ │
│        └─────────────┬┘──────────────┘      │
│                  ┌────▼─────┐               │
│                  │ Evidence │               │
│                  │ Emitter  │               │
│                  └────┬─────┘               │
│                       │                     │
└───────────────────────┼─────────────────────┘
                        ▼
                stdout / file (JSON lines)
```

### Components

1. **Capture** — AF_PACKET with MMAP ring buffer on specified interface. Zero-copy, read-only. No nftables rules needed.

2. **Parser** — Extracts metadata from each frame: IP src/dst, TCP flags/seq/ack/window, TTL, packet size. Optionally
   extracts SNI from TLS ClientHello (as metadata, not for filtering). No payload inspection beyond TLS handshake.

3. **Flow Table** — Keyed by `(dst_ip, dst_port)`. Per-flow state: TTL baseline, bytes transferred, timestamps, TCP
   state, retransmit counter. Flows expire after configurable TTL (default 120s).

4. **Three Detectors** — Each runs on every packet update to a flow:
    - **Injection Detector**: RST/FIN/window with TTL anomaly, duplicate DNS/HTTP responses
    - **Drop Detector**: SYN timeout, post-ClientHello silence with retransmissions
    - **Throughput Detector**: byte-count cliff, retransmission ratio, asymmetric drops

5. **Evidence Emitter** — Formats and outputs signals. stdout by default (human-readable), or JSON lines to file. Each
   line = one evidence event for one dst_ip.

### What flowsense is NOT

- Not a packet filter (doesn't touch traffic)
- Not a DPI engine (doesn't classify protocols by payload)
- Not stateful in the IDS sense (no signature database, no rules)

---

## Detection Catalog

10 techniques, 3 detectors.

### Injection Detector

Looks for packets that don't belong — wrong TTL, unexpected timing, duplicates.

| Signal                    | Trigger                                                                        | Key evidence fields                                        |
|---------------------------|--------------------------------------------------------------------------------|------------------------------------------------------------|
| `RST_INJECTION`           | RST within `injection_window` after ClientHello, TTL anomaly > `ttl_tolerance` | `ttl_expected`, `ttl_actual`, `delta_ms`, `salvo_count`    |
| `FIN_INJECTION`           | Unexpected FIN with TTL anomaly, connection was active                         | `ttl_expected`, `ttl_actual`                               |
| `WINDOW_MANIPULATION`     | Packet with window=0 or window=1, TTL anomaly                                  | `ttl_expected`, `ttl_actual`, `window_value`               |
| `DNS_POISONING`           | Duplicate DNS response to same query, first response TTL differs               | `ttl_first`, `ttl_second`, `answer_first`, `answer_second` |
| `HTTP_REDIRECT_INJECTION` | Duplicate HTTP response (302), TTL anomaly                                     | `ttl_expected`, `ttl_actual`, `redirect_target`            |

Common pattern: **TTL anomaly + timing/duplication**. One engine, five signal types.

### Drop Detector

Looks for absence — sent something, got nothing back.

| Signal         | Trigger                                                                                | Key evidence fields                    |
|----------------|----------------------------------------------------------------------------------------|----------------------------------------|
| `IP_BLACKHOLE` | SYN sent, no SYN+ACK within `syn_timeout`, all ports affected                          | `syn_retransmits`, `ports_tried`       |
| `SILENT_DROP`  | ClientHello sent, no ServerHello within `post_hello_timeout`, retransmissions observed | `retransmit_count`, `has_client_hello` |

Common pattern: **retransmissions + timeout**. Distinction: IP_BLACKHOLE fails at SYN, SILENT_DROP fails after
handshake.

### Throughput Detector

Looks for degradation — data was flowing, then stopped or slowed.

| Signal                   | Trigger                                                                                         | Key evidence fields                                             |
|--------------------------|-------------------------------------------------------------------------------------------------|-----------------------------------------------------------------|
| `THROTTLE_CLIFF`         | Bytes transferred > 0, then no new data for `cliff_timeout`, total bytes near `cliff_threshold` | `bytes_before_cliff`, `stall_duration`                          |
| `THROTTLE_PROBABILISTIC` | Retransmission ratio > `retransmit_ratio` over `throttle_window`                                | `retransmit_ratio`, `throughput_bps`, `expected_throughput_bps` |
| `ACK_DROP`               | Server data packets arrive, but server retransmits increase (ACKs not reaching server)          | `server_retransmits`, `client_data_ok`, `asymmetric`            |

Common pattern: **bytes/time analysis + retransmission patterns**.

Each detector emits evidence independently. One flow can produce multiple signals — e.g., `RST_INJECTION` +
`THROTTLE_CLIFF` if DPI tries throttle first, then RST.

---

## CLI Interface

tcpdump-style. One mode: capture and output.

### Usage

```
flowsense -i <interface> [options]

CAPTURE:
  -i <interface>        Network interface to listen on (required unless -r)
  -r <file>             Read from pcap file instead of live capture
  -w <file>             Write evidence to file (JSON lines)
  -c <count>            Stop after <count> evidence events
  --duration <seconds>  Stop after <seconds>

FILTERING:
  --dst <ip>            Only track flows to this destination IP
  --port <port>         Only track flows to this destination port

OUTPUT:
  --json                JSON lines output (default for -w, human-readable for stdout)
  -v                    Verbose — include flow metadata (SNI, bytes, timing)
  -q                    Quiet — only confirmed signals, no warnings

CONFIG:
  --config <file>       Load thresholds from JSON config file
  --print-config        Print default config and exit
```

### Examples

```bash
# Basic — watch everything on bridge
flowsense -i br-lan

# JSON output for piping
flowsense -i br-lan --json

# Focus on one server
flowsense -i br-lan --dst 142.250.74.46 -v

# Analyze existing capture
flowsense -r /tmp/capture.pcap

# Run for 60 seconds, save results
flowsense -i br-lan --duration 60 -w /tmp/evidence.jsonl
```

### Output formats

**Human-readable (stdout default):**

```
[14:23:01] 100.21.56.3:443    RST_INJECTION       ttl=52→61 salvo=3 after_hello=12ms
[14:23:05] 194.10.20.30:443   THROTTLE_CLIFF      bytes=16384 stall=3.2s
[14:23:12] 123.45.67.89:443   SILENT_DROP          retransmits=5 post_hello
[14:23:30] 88.12.44.5:80      HTTP_REDIRECT_INJ    ttl=52→60 redirect=block.page.ru
```

**JSON lines (--json or -w):**

```json
{
  "ts": 1712178181,
  "dst_ip": "100.21.56.3",
  "dst_port": 443,
  "signal": "RST_INJECTION",
  "evidence": {
    "ttl_expected": 52,
    "ttl_actual": 61,
    "salvo_count": 3,
    "delta_ms": 12
  },
  "sni": "discord.com"
}
```

SNI included as optional metadata when available (seen in ClientHello). Not used for detection logic.

---

## Flow Table & State Machine

### Flow Key

```
(dst_ip, dst_port) → FlowState
```

### Flow State Machine

```
          SYN seen
              │
              ▼
         SYN_SENT ──── no SYN+ACK within syn_timeout ──→ emit IP_BLACKHOLE
              │
         SYN+ACK seen (record TTL baseline)
              │
              ▼
        ESTABLISHED
              │
              ├── ClientHello seen ──→ mark has_client_hello, record SNI
              │
              ├── RST with TTL anomaly ──→ emit RST_INJECTION
              ├── FIN with TTL anomaly ──→ emit FIN_INJECTION
              ├── Window 0/1 + TTL anomaly ──→ emit WINDOW_MANIPULATION
              │
              ├── no response after ClientHello within post_hello_timeout
              │   + retransmissions ──→ emit SILENT_DROP
              │
              ├── data flowing ──→ transition to TRANSFERRING
              │
              ▼
        TRANSFERRING
              │
              ├── bytes > cliff_threshold, then stall > cliff_timeout
              │   ──→ emit THROTTLE_CLIFF
              │
              ├── retransmit_ratio > threshold over throttle_window
              │   ──→ emit THROTTLE_PROBABILISTIC
              │
              ├── server retransmits but client→server ok
              │   ──→ emit ACK_DROP
              │
              ├── RST/FIN with TTL anomaly ──→ emit injection signal
              │
              ▼
          FINISHED (FIN/RST or timeout)
              │
              after flow_ttl ──→ evict from table
```

### Multiple connections to same (dst_ip, dst_port)

Flow table tracks **aggregate state**. Multiple TCP connections to same destination merge into one flow entry. Signals
accumulate — if 3 out of 5 connections to same server get RST injected, evidence shows `count=3`.

Fresh connections reset byte counters but preserve TTL baseline and signal history until flow expires.

### DNS/HTTP flows (UDP 53, TCP 80)

Same table, but:

- DNS: keyed by `(dst_ip, 53)`. Injection detector watches for duplicate responses.
- HTTP: keyed by `(dst_ip, 80)`. Injection detector watches for duplicate 302 responses.
- No state machine needed — single request/response, just duplicate detection.

---

## Configuration

JSON config file. All values have sensible defaults — flowsense works out of the box with zero config.

```json
{
  "capture": {
    "snaplen": 128,
    "promisc": true
  },
  "detection": {
    "drop": {
      "syn_timeout": 5,
      "post_hello_timeout": 10
    },
    "injection": {
      "ttl_tolerance": 2,
      "injection_window": 500
    },
    "throughput": {
      "cliff_threshold": 20480,
      "cliff_timeout": 3,
      "throttle_window": 10,
      "retransmit_ratio": 0.3
    }
  },
  "flows": {
    "flow_ttl": 120,
    "max_flows": 50000
  }
}
```

- `snaplen = 128` — 14 (Ethernet) + 20 (IP) + 20 (TCP) + ~74 (enough to parse SNI from ClientHello). Minimizes memory
  and CPU.
- All thresholds are configurable. Defaults are starting points based on observed DPI behavior.

---

## Technology & Build

**Language:** Rust

- Static binary (musl), no runtime dependencies
- Cross-compile to any target supported by Rust (x86_64, aarch64, mips, etc.)
- AF_PACKET via `libc` crate directly (no libpcap dependency)
- Zero allocations in hot path (packet parsing)

**Dependencies (minimal):**

| Crate                  | Purpose                            |
|------------------------|------------------------------------|
| `libc`                 | AF_PACKET socket, MMAP ring buffer |
| `serde` + `serde_json` | JSON config & output               |
| `clap`                 | CLI argument parsing               |

No async runtime. Synchronous packet loop — `poll()` on AF_PACKET fd, parse, update flow table, emit. Simple and
predictable.

**pcap support (`-r` flag):**

| Crate         | Purpose                       |
|---------------|-------------------------------|
| `pcap-parser` | Parse pcap/pcapng file format |

Feature-gated: `--features pcap`. Not included by default to keep binary size minimal.

**Build:**

```bash
# Native
cargo build --release

# Cross-compile
cross build --release --target <target-triple>

# With pcap support
cargo build --release --features pcap
```

Expected binary size: ~500KB–1MB stripped.

---

## Testing Strategy

### Unit tests

Per detector, with crafted packet sequences:

```rust
#[test]
fn test_rst_injection_detected_by_ttl_anomaly() {
    let mut flow_table = FlowTable::new(Config::default());

    // SYN+ACK from server, TTL=52
    flow_table.update(packet(SYN_ACK, dst=SERVER, ttl=52));
    // ClientHello
    flow_table.update(packet(PSH_ACK, dst=SERVER, payload=CLIENT_HELLO));
    // RST with wrong TTL
    let signals = flow_table.update(packet(RST, src=SERVER, ttl=61));

    assert_eq!(signals[0].signal_type, SignalType::RstInjection);
    assert_eq!(signals[0].evidence.ttl_expected, 52);
    assert_eq!(signals[0].evidence.ttl_actual, 61);
}
```

Test cases per detector:

- **Injection**: RST with TTL anomaly, RST with normal TTL (should NOT trigger), FIN injection, window manipulation, DNS
  duplicate, HTTP 302 duplicate
- **Drop**: SYN timeout, post-ClientHello silence, normal slow server (should NOT trigger)
- **Throughput**: 16KB cliff, probabilistic throttle, ACK drop, normal bursty traffic (should NOT trigger)

### False positive tests (critical)

- Slow server ≠ throttle
- ECMP routing TTL jitter ≠ injection
- Server-initiated RST (e.g. 404) ≠ RST injection
- Legitimate FIN ≠ FIN injection

### Integration tests

Feed pcap files with known DPI interference through `-r`:

```bash
# Captured RST injection from real DPI
flowsense -r tests/fixtures/dpi-rst-injection.pcap --json
# Expected: RST_INJECTION signal

# Clean traffic, no interference
flowsense -r tests/fixtures/clean-traffic.pcap --json
# Expected: no signals
```

pcap fixtures collected from real networks or crafted with scapy.

---

## Non-goals & Boundaries

What flowsense explicitly **does not do**:

- **Does not modify traffic** — read-only AF_PACKET, zero impact on user's connection
- **Does not inspect payload** — only headers + TLS ClientHello SNI. No DPI.
- **Does not make decisions** — emits evidence, never acts on it. No "block this", no "reroute that"
- **Does not phone home** — no network connections, no telemetry, no updates
- **Does not require nftables rules** — works independently from any firewall config
- **Does not depend on external services** — no backend, no API, no database
- **Does not track users** — no src_ip in output, no MAC addresses, no device fingerprinting
- **Linux only** — AF_PACKET is a Linux kernel feature
