//! Flow table: tracks TCP/UDP connections aggregated by (dst_ip, dst_port).
//!
//! This is the central state machine of FlowSense. Every packet captured on
//! the bridge interface updates a flow entry here. Detectors in detect/ then
//! inspect flow state to decide whether DPI interference is happening.
//!
//! # Architecture
//!
//! ```text
//!   AF_PACKET (br0)
//!       │
//!       ▼
//!   parser::parse()  →  ParsedPacket
//!       │
//!       ▼
//!   FlowTable::update()  →  updates FlowState for (dst_ip, dst_port)
//!       │
//!       ├──► detect::injection::detect()    [per-packet, immediate]
//!       └──► detect::drop::detect_timeout() [periodic, every 5s]
//!            detect::throughput::*()
//! ```
//!
//! # Flow key
//!
//! All connections to the same (dst_ip, dst_port) share one FlowState.
//! The "destination" is always the server side — `classify_direction()` flips
//! src/dst for server-originated packets so the key is consistent.
//!
//! # State machine
//!
//! ```text
//!   SYN sent ──► SynSent ──SYN-ACK──► Established ──data──► Transferring
//!                   │                      │                      │
//!                   │ (timeout)            │ (RST/FIN/timeout)   │ (FIN/RST)
//!                   ▼                      ▼                      ▼
//!              [IP_BLACKHOLE]         [RST/FIN_INJECTION]    [THROTTLE_*]
//!                                    [SILENT_DROP]
//! ```

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::config::FlowsConfig;
use crate::parser::ParsedPacket;

/// Uniquely identifies a flow by server destination.
///
/// Note: the key is (server_ip, server_port), NOT (client_ip, client_port).
/// This means all connections from tinyproxy to the same server:443 merge
/// into one flow. For our use case this is correct — we care about the
/// server, not which client socket initiated the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

/// Lifecycle phase of a tracked flow.
///
/// Transitions are driven by TCP flags and payload in `FlowTable::update()`.
/// Detectors check the phase to decide which signals are applicable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPhase {
    /// SYN sent by client, waiting for SYN-ACK from server.
    /// If stuck here: potential IP_BLACKHOLE.
    SynSent,

    /// TCP handshake complete (SYN-ACK received), TTL baseline recorded.
    /// ClientHello may or may not have been sent yet.
    /// If ClientHello sent but no data: potential SILENT_DROP or RST_INJECTION.
    Established,

    /// Server has started sending payload data (bytes_rx > 0).
    /// Throughput detectors (cliff, retransmit, ACK drop) operate here.
    Transferring,

    /// Connection has ended (FIN/RST or timeout). Awaiting expiry from table.
    Finished,
}

/// Packet direction relative to the server.
///
/// Determined heuristically by `classify_direction()`. Not always correct
/// (see comments on that function), but reliable for port 443 traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    FromClient,
    FromServer,
}

/// Per-flow state tracked across packets.
///
/// Updated by `FlowTable::update()` on every packet. Read by detectors.
/// All timestamps are in seconds from CLOCK_MONOTONIC epoch (see time.rs).
#[derive(Debug, Clone)]
pub struct FlowState {
    /// Current lifecycle phase (SynSent → Established → Transferring → Finished)
    pub phase: FlowPhase,

    /// TTL from the first SYN-ACK packet (server's real TTL).
    /// Used by injection detector to spot TTL anomalies in RST/FIN/window packets.
    /// None until SYN-ACK is seen.
    pub ttl_baseline: Option<u8>,

    /// True if we've seen a TLS ClientHello in this flow.
    /// Set only once (first ClientHello), retransmits don't flip this again.
    pub has_client_hello: bool,

    /// Timestamp of the FIRST ClientHello (not updated on retransmits!).
    /// Used by SILENT_DROP to measure how long we've been waiting for server response.
    /// Critical: if retransmits updated this, the timer would never expire.
    pub client_hello_ts: Option<f64>,

    /// TLS SNI extracted from ClientHello (e.g. "discord.com").
    /// Included in signal output for human-readable evidence.
    pub sni: Option<String>,

    /// Total bytes received from server (payload only, no headers).
    /// Used to distinguish "no data" (potential drop) from "data flowing" (transfer).
    pub bytes_rx: u64,

    /// Total bytes sent to server by client (payload only).
    /// Used by ACK_DROP detector to confirm client is still sending.
    pub bytes_tx: u64,

    /// Timestamp of first server data packet (phase transition to Transferring).
    /// Used by retransmit ratio calculation as the start of the observation window.
    pub first_data_ts: Option<f64>,

    /// Timestamp of most recent server data packet.
    /// Used by cliff detector to measure stall duration.
    pub last_data_ts: Option<f64>,

    /// Timestamp of any activity (any packet in either direction).
    /// Used for flow expiry (evict after flow_ttl seconds of silence).
    pub last_activity_ts: f64,

    /// Timestamp when the flow was created (first SYN).
    /// Used by IP_BLACKHOLE to measure how long SYN has been waiting.
    pub syn_ts: f64,

    /// Client-side retransmit counter:
    ///   - In SynSent phase: counts SYN retransmits (no SYN-ACK response)
    ///   - In Established phase: counts ClientHello retransmits (no server data)
    ///
    /// Used by IP_BLACKHOLE (requires ≥1) and SILENT_DROP (evidence).
    pub retransmit_count: u32,

    /// Server-side retransmit counter: same TCP seq seen twice from server.
    /// Indicates packet loss or DPI-induced retransmissions.
    /// Used by THROTTLE_PROBABILISTIC and ACK_DROP detectors.
    pub server_retransmit_count: u32,

    /// Count of RST packets seen from server direction.
    /// TSPU may send multiple RSTs ("salvo"). Counted as one event in injection detector.
    /// Also used by SILENT_DROP: if rst_salvo > 0, RST_INJECTION handles it instead.
    pub rst_salvo_count: u32,

    /// Last TCP sequence number from server. Used to detect retransmits:
    /// if the same seq arrives twice, the second is a retransmit.
    pub last_seq_from_server: Option<u32>,

    /// Fire-once flag for time-based signals (IP_BLACKHOLE, SILENT_DROP, etc.).
    /// Set by main.rs via `mark_signal_fired()` after emitting a timeout signal.
    /// Prevents the same flow from generating repeated signals every 5 seconds.
    pub timeout_signal_fired: bool,
}

impl FlowState {
    fn new(syn_ts: f64) -> Self {
        Self {
            phase: FlowPhase::SynSent,
            ttl_baseline: None,
            has_client_hello: false,
            client_hello_ts: None,
            sni: None,
            bytes_rx: 0,
            bytes_tx: 0,
            first_data_ts: None,
            last_data_ts: None,
            last_activity_ts: syn_ts,
            syn_ts,
            retransmit_count: 0,
            server_retransmit_count: 0,
            rst_salvo_count: 0,
            last_seq_from_server: None,
            timeout_signal_fired: false,
        }
    }
}

/// Returns true for RFC 1918 private, loopback, and link-local addresses.
///
/// Used by all detectors to skip container-internal traffic:
///   - 10.99.0.x  = our bridge subnet (tinyproxy ↔ flowsense)
///   - 172.16-31.x = docker bridge networks (172.17.0.1 gateway)
///   - 192.168.x  = other private ranges
///   - 127.x      = loopback
///
/// Without this filter, internal traffic between tinyproxy and flowsense
/// would trigger false positives (IP_BLACKHOLE on docker gateway,
/// THROTTLE_CLIFF on idle tinyproxy connections, etc.).
pub fn is_private_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [10, ..] | [172, 16..=31, ..] | [192, 168, ..] | [127, ..]
    )
}

/// The flow table: maps (dst_ip, dst_port) → FlowState.
///
/// Owns all flow state. Updated on every packet, queried by detectors.
/// Flows are evicted after flow_ttl (120s) of inactivity.
pub struct FlowTable {
    config: FlowsConfig,
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTable {
    pub fn new(config: FlowsConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
        }
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowState> {
        self.flows.get(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn config(&self) -> &FlowsConfig {
        &self.config
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowState)> {
        self.flows.iter()
    }

    /// Mark a flow as having fired a timeout signal (fire-once).
    /// Called by main.rs after emitting IP_BLACKHOLE, SILENT_DROP, etc.
    pub fn mark_signal_fired(&mut self, key: &FlowKey) {
        if let Some(flow) = self.flows.get_mut(key) {
            flow.timeout_signal_fired = true;
        }
    }

    /// Process one parsed packet: create or update the matching flow.
    ///
    /// This is the heart of the flow state machine. Packet processing order:
    ///   1. Look up or create flow by (dst_ip, dst_port)
    ///   2. Update last_activity_ts (for expiry)
    ///   3. Handle SYN-ACK → Established transition
    ///   4. Track SYN retransmits (SynSent phase)
    ///   5. Match on (phase, direction, flags) for state transitions
    pub fn update(&mut self, pkt: &ParsedPacket, ts: f64) {
        let key = flow_key_from_packet(pkt);
        let direction = classify_direction(pkt);

        // Create flow on first SYN, or look up existing flow for this server.
        let flow = self.flows.entry(key).or_insert_with(|| FlowState::new(ts));
        flow.last_activity_ts = ts;

        let phase = flow.phase;
        let flags = pkt.tcp_flags;
        let payload = pkt.payload_len;

        // ─── SYN-ACK handling ──────────────────────────────────────
        // Transition SynSent → Established and record TTL baseline.
        // Done outside the main match because the direction heuristic for
        // SYN-ACK can be unreliable when both directions share the same
        // flow key (which they do, by design).
        if phase == FlowPhase::SynSent && flags.is_syn_ack() {
            flow.phase = FlowPhase::Established;
            // Record server's real TTL from SYN-ACK.
            // This becomes the baseline for injection detection.
            // TSPU-injected packets will have a different TTL.
            flow.ttl_baseline = Some(pkt.ttl);
            return;
        }

        // ─── SYN retransmit tracking ──────────────────────────────
        // If we're still in SynSent and see another SYN from the client,
        // it's a TCP retransmit (kernel retries after no SYN-ACK).
        // IP_BLACKHOLE detector requires retransmit_count ≥ 1 to avoid
        // false positives on fresh flows that just haven't got SYN-ACK yet.
        //
        // Guard: only count as retransmit if this isn't the first SYN
        // (last_activity_ts > syn_ts means we've seen at least one update).
        if phase == FlowPhase::SynSent
            && direction == Direction::FromClient
            && flags.has_syn()
            && flow.last_activity_ts > flow.syn_ts
        {
            flow.retransmit_count += 1;
        }

        // ─── Main state machine ───────────────────────────────────
        match (phase, direction, flags) {
            // ClientHello from client → record TLS metadata.
            // CRITICAL: only record timestamp on FIRST ClientHello!
            // TCP retransmits carry the same has_client_hello=true flag.
            // If we updated client_hello_ts on retransmits, the SILENT_DROP
            // timer would reset every 3-6 seconds and never expire.
            // Instead, retransmits increment retransmit_count.
            (FlowPhase::Established, Direction::FromClient, _) if pkt.has_client_hello => {
                if !flow.has_client_hello {
                    // First ClientHello — record timestamp and SNI
                    flow.has_client_hello = true;
                    flow.client_hello_ts = Some(ts);
                    if pkt.sni.is_some() {
                        flow.sni = pkt.sni.clone();
                    }
                }
                // Subsequent ClientHello retransmits
                else {
                    flow.retransmit_count += 1;
                }
            }

            // First server data → transition to Transferring.
            // This means the TLS handshake completed and real data is flowing.
            // Once here, injection/drop detectors stop (connection is working).
            (FlowPhase::Established, Direction::FromServer, _) if payload > 0 => {
                flow.phase = FlowPhase::Transferring;
                track_server_data(flow, pkt, ts);
            }

            // Subsequent server data in Transferring phase.
            (FlowPhase::Transferring, Direction::FromServer, _) if payload > 0 => {
                track_server_data(flow, pkt, ts);
            }

            // FIN or RST from server in Transferring phase → transition to Finished.
            // This prevents THROTTLE_CLIFF from firing on normally-closed connections.
            // FIN = graceful close (server sent all data).
            // RST in Transferring = server-side teardown after data transfer
            // (some servers send RST instead of FIN, e.g. CDN connection reuse).
            // Note: RST in Established phase is NOT transitioned here — that's
            // handled by the rst_salvo_count branch below (injection detection).
            (FlowPhase::Transferring, Direction::FromServer, _)
                if flags.has_fin() || flags.has_rst() =>
            {
                flow.phase = FlowPhase::Finished;
                if flags.has_rst() {
                    flow.rst_salvo_count += 1;
                }
            }

            // RST from server direction → count for salvo detection.
            // The injection detector reads rst_salvo_count to report how many
            // RST packets were in the "salvo" (TSPU often sends 1-3).
            // Also used by SILENT_DROP: if rst_salvo > 0, skip (RST_INJECTION handles it).
            (_, Direction::FromServer, _) if flags.has_rst() => {
                flow.rst_salvo_count += 1;
            }

            // Client payload → track bytes_tx for ACK_DROP evidence.
            (_, Direction::FromClient, _) if payload > 0 => {
                flow.bytes_tx += payload as u64;
            }

            _ => {}
        }
    }

    /// Remove flows that have been inactive for longer than flow_ttl.
    /// Called from periodic check in main.rs. Default flow_ttl = 120 seconds.
    pub fn expire(&mut self, now: f64) {
        let ttl = self.config.flow_ttl;
        self.flows
            .retain(|_, state| now - state.last_activity_ts < ttl);
    }
}

/// Heuristic to determine packet direction (client→server or server→client).
///
/// Rules (in priority order):
///   1. SYN-ACK → always from server (it's a response to client's SYN)
///   2. SYN (no ACK) → always from client (initiating connection)
///   3. dst_port < 1024 → likely from client (connecting to well-known port like 443)
///   4. Otherwise → assume from server (response from well-known port to ephemeral port)
///
/// This heuristic works well for HTTPS on port 443 (our primary use case).
/// It can misclassify on non-standard ports or P2P traffic.
fn classify_direction(pkt: &ParsedPacket) -> Direction {
    if pkt.tcp_flags.is_syn_ack() {
        return Direction::FromServer;
    }
    if pkt.tcp_flags.has_syn() {
        return Direction::FromClient;
    }
    if pkt.dst_port < 1024 {
        return Direction::FromClient;
    }
    Direction::FromServer
}

/// Derive the flow key from a packet, normalizing direction.
///
/// For client→server packets: key = (pkt.dst_ip, pkt.dst_port) = the server.
/// For server→client packets: key = (pkt.src_ip, pkt.src_port) = still the server.
///
/// This ensures both directions of a connection map to the same FlowState.
pub fn flow_key_from_packet(pkt: &ParsedPacket) -> FlowKey {
    let dir = classify_direction(pkt);
    match dir {
        Direction::FromClient => FlowKey {
            dst_ip: pkt.dst_ip,
            dst_port: pkt.dst_port,
        },
        Direction::FromServer => FlowKey {
            dst_ip: pkt.src_ip,
            dst_port: pkt.src_port,
        },
    }
}

/// Track server data packet: update bytes received, timestamps, and retransmit detection.
///
/// Retransmit detection: if the TCP sequence number matches the last one we saw,
/// the server is retransmitting (packet was lost or ACK was dropped by DPI).
/// Otherwise it's new data — increment bytes_rx and update timestamps.
fn track_server_data(flow: &mut FlowState, pkt: &ParsedPacket, ts: f64) {
    let payload = pkt.payload_len as u64;

    match flow.last_seq_from_server {
        // Same seq as last packet → retransmit (server didn't get our ACK)
        Some(last_seq) if last_seq == pkt.tcp_seq => {
            flow.server_retransmit_count += 1;
        }
        // New seq → fresh data
        _ => {
            flow.bytes_rx += payload;
            flow.last_seq_from_server = Some(pkt.tcp_seq);
            if flow.first_data_ts.is_none() {
                flow.first_data_ts = Some(ts);
            }
            flow.last_data_ts = Some(ts);
        }
    }
}
