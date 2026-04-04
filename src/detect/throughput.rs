//! Time-based throughput degradation detector.
//!
//! Runs on a periodic timer (every 5 seconds) alongside drop.rs.
//! Detects three patterns of DPI-induced throughput degradation:
//!
//! ```text
//!   THROTTLE_CLIFF         — Data was flowing, then abruptly stopped.
//!                            DPI may kill the flow mid-transfer (e.g. YouTube throttling).
//!                            Triggers when: bytes received ≥ min_bytes, then stall ≥ timeout,
//!                            total bytes ≤ 2× cliff_threshold (small transfer, not a big download).
//!
//!   THROTTLE_PROBABILISTIC — High retransmit ratio indicates packet loss / interference.
//!                            DPI may selectively drop packets to degrade quality.
//!                            Triggers when: retransmit ratio ≥ 30%, ≥5 packets, window ≥ 10s.
//!
//!   ACK_DROP               — Server retransmits heavily but client is still sending.
//!                            DPI may drop ACKs in one direction (asymmetric interference).
//!                            Triggers when: server_retransmits ≥ 5, ratio ≥ 30%, bytes_tx > 0.
//! ```
//!
//! All three skip private/loopback IPs to avoid false positives on container-internal
//! traffic (tinyproxy on 10.99.0.2, docker bridge on 172.17.0.x).
//!
//! E2E status (2026-04): not yet validated against real throttled domains.
//! YouTube throttling and similar scenarios need testing.

use crate::config::Config;
use crate::flow::{is_private_ip, FlowKey, FlowPhase, FlowState};
use crate::signal::Signal;

/// Detect a sudden stop in data flow ("bandwidth cliff").
///
/// Pattern: server was sending data (phase=Transferring, bytes_rx > 0),
/// then stopped for ≥ cliff_timeout seconds. This suggests DPI killed the
/// flow mid-transfer rather than at the TLS handshake stage.
///
/// Thresholds:
///   - cliff_min_bytes (4KB): minimum data before we consider it a "transfer"
///   - cliff_threshold (20KB): maximum bytes for a "small transfer" cliff
///     (large downloads stalling could be normal network congestion)
///   - cliff_timeout (3s): how long the stall must last
pub fn detect_cliff(flow: &FlowState, key: &FlowKey, config: &Config, now: f64) -> Option<Signal> {
    // Skip container-internal traffic (tinyproxy, docker bridge)
    if is_private_ip(key.dst_ip) {
        return None;
    }
    // Fire-once: don't repeat on the same flow
    if flow.timeout_signal_fired {
        return None;
    }
    let cfg = &config.detection.throughput;

    // Only check flows that were actively transferring data
    (flow.phase == FlowPhase::Transferring)
        .then_some(flow.last_data_ts)
        .flatten()
        .and_then(|last_data| {
            let stall = now - last_data;

            // Three conditions for cliff detection:
            //   1. Stall duration exceeds threshold (data stopped flowing)
            //   2. Enough bytes were received to confirm a real transfer started
            //   3. Total bytes is small enough that this isn't just a download pause
            //      (large downloads can legitimately stall due to congestion)
            let cliff_condition = stall >= cfg.cliff_timeout
                && flow.bytes_rx >= cfg.cliff_min_bytes
                && flow.bytes_rx <= cfg.cliff_threshold * 2;

            cliff_condition.then(|| Signal::ThrottleCliff {
                ts: now,
                dst_ip: key.dst_ip.to_string(),
                dst_port: key.dst_port,
                sni: flow.sni.clone(),
                bytes_before_cliff: flow.bytes_rx,
                stall_duration: stall,
            })
        })
}

/// Detect statistically anomalous retransmission rate.
///
/// Pattern: over the throttle_window (10s), the server retransmit ratio exceeds
/// retransmit_ratio (30%). High retransmission suggests DPI is selectively dropping
/// packets to degrade throughput without completely killing the connection.
///
/// Requires ≥5 total packets to avoid triggering on tiny flows where one retransmit
/// would be 50% ratio. Throughput (bps) included as evidence for context.
pub fn detect_retransmit(
    flow: &FlowState,
    key: &FlowKey,
    config: &Config,
    now: f64,
) -> Option<Signal> {
    // Skip container-internal traffic
    if is_private_ip(key.dst_ip) {
        return None;
    }
    let cfg = &config.detection.throughput;

    // Only check flows in Transferring phase (data was flowing)
    (flow.phase == FlowPhase::Transferring)
        .then_some(flow.first_data_ts)
        .flatten()
        .and_then(|first_data| {
            let window = now - first_data;
            let total_packets = flow.server_retransmit_count + 1; // +1 for the original
            let ratio = flow.server_retransmit_count as f64 / total_packets as f64;

            let condition = window >= cfg.throttle_window
                && total_packets >= 5
                && ratio >= cfg.retransmit_ratio;

            condition.then(|| {
                // Calculate throughput for evidence/context
                let throughput_bps = if window > 0.0 {
                    (flow.bytes_rx as f64 * 8.0) / window
                } else {
                    0.0
                };
                Signal::ThrottleProbabilistic {
                    ts: now,
                    dst_ip: key.dst_ip.to_string(),
                    dst_port: key.dst_port,
                    sni: flow.sni.clone(),
                    retransmit_ratio: ratio,
                    throughput_bps,
                    server_retransmits: flow.server_retransmit_count,
                }
            })
        })
}

/// Detect asymmetric ACK dropping.
///
/// Pattern: server is retransmitting heavily (server_retransmit_count ≥ 5)
/// but client is still sending data (bytes_tx > 0). This suggests DPI is
/// dropping ACKs from client → server, causing the server to think packets
/// were lost and retransmit, while the client keeps sending normally.
///
/// This is a more specific form of throttling than probabilistic — it points
/// to directional packet dropping rather than random loss.
pub fn detect_ack_drop(
    flow: &FlowState,
    key: &FlowKey,
    config: &Config,
    _now: f64,
) -> Option<Signal> {
    // Skip container-internal traffic
    if is_private_ip(key.dst_ip) {
        return None;
    }
    let cfg = &config.detection.throughput;

    let total_packets = flow.server_retransmit_count + 1;
    let ratio = flow.server_retransmit_count as f64 / total_packets as f64;

    let condition = flow.phase == FlowPhase::Transferring
        && flow.server_retransmit_count > 5
        && flow.bytes_tx > 0
        && ratio >= cfg.retransmit_ratio;

    condition.then(|| Signal::AckDrop {
        ts: _now,
        dst_ip: key.dst_ip.to_string(),
        dst_port: key.dst_port,
        sni: flow.sni.clone(),
        server_retransmits: flow.server_retransmit_count,
    })
}
