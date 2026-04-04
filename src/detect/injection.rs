//! Packet-based injection detector.
//!
//! Fires immediately when a suspicious packet arrives (RST, FIN, or window=0/1).
//! This detector runs on every incoming packet, NOT on a periodic timer.
//!
//! Detection strategy overview:
//!
//! ```text
//!   Server ──SYN-ACK──► FlowSense records TTL baseline (e.g. 107)
//!   Client ──ClientHello──► FlowSense records hello_ts
//!   TSPU   ──RST──────► TTL=52 (differs from baseline!) → RST_INJECTION
//! ```
//!
//! Two independent criteria for RST injection:
//!   1. TTL anomaly  — RST TTL differs from server baseline by ≥ tolerance (2 hops)
//!   2. Timing-only  — RST arrives ≤50ms after ClientHello, no server data yet
//!      (catches Cloudflare domains where TSPU TTL ≈ server TTL)
//!
//! Observed TSPU fingerprint (Russia, 2026-04):
//!   - All injected RSTs have ttl=52, delta_ms=0 regardless of real server TTL
//!   - Works on SNI-blocked domains (porn, torrents, social media, news)

use crate::config::Config;
use crate::flow::FlowState;
use crate::parser::ParsedPacket;
use crate::signal::Signal;

/// Heuristic: is this packet traveling client → server?
///
/// Used to skip client-originated RST/FIN (e.g. browser tab close, curl timeout)
/// which would have the client's TTL and cause false positives.
///
/// Logic:
///   - SYN-ACK is always server → client
///   - SYN (without ACK) is always client → server
///   - dst_port < 1024 (well-known) → likely client → server
///   - Otherwise → assume server → client
///
/// This heuristic can misclassify on non-standard ports, but for DPI detection
/// on port 443 it works reliably.
fn is_from_client(pkt: &ParsedPacket) -> bool {
    if pkt.tcp_flags.is_syn_ack() {
        return false;
    }
    if pkt.tcp_flags.has_syn() {
        return true;
    }
    pkt.dst_port < 1024
}

/// Returns true if the TTL difference exceeds the tolerance threshold.
///
/// TSPU devices sit at a fixed network hop and respond with their own TTL (typically 52).
/// Real servers have TTL determined by their OS and distance:
///   - Linux default: 64, Windows: 128, distant servers: varies
///   - Nearby CDN (Cloudflare PoP in Russia): TTL ≈ 51-53 (similar to TSPU!)
///
/// Default tolerance = 2 hops. Works well for distant servers (LinkedIn TTL=107),
/// fails for nearby Cloudflare (TTL=53 vs TSPU TTL=52, delta=1 < tolerance).
fn ttl_anomaly(actual: u8, baseline: u8, tolerance: u8) -> bool {
    actual.abs_diff(baseline) >= tolerance
}

/// Main injection detection entry point. Called on every parsed packet.
///
/// Returns Some(Signal) if the packet looks like a DPI-injected RST/FIN/window trick.
/// Returns None for normal traffic, client-originated packets, or inconclusive cases.
pub fn detect(pkt: &ParsedPacket, flow: &FlowState, config: &Config, ts: f64) -> Option<Signal> {
    // Skip client → server packets entirely.
    // We only care about server → client direction where TSPU injects fake packets.
    if is_from_client(pkt) {
        return None;
    }

    // Need a TTL baseline from SYN-ACK to compare against.
    // If we haven't seen SYN-ACK yet (flow in SynSent), we can't detect injection.
    let baseline = flow.ttl_baseline?;
    let tolerance = config.detection.injection.ttl_tolerance;
    let has_ttl_anomaly = ttl_anomaly(pkt.ttl, baseline, tolerance);

    // --- Timing context ---
    // "Post-hello, no data" = ClientHello was sent but server hasn't responded yet.
    // This is the critical window where TSPU injects RST/FIN before the real server
    // can respond. If server already sent data (bytes_rx > 0), the connection is
    // working and any RST/FIN is more likely legitimate (server error, etc).
    let post_hello_no_data = flow.client_hello_ts.is_some() && flow.bytes_rx == 0;

    // How many milliseconds since ClientHello was sent?
    let delta_ms_from_hello = flow.client_hello_ts.map(|hello_ts| {
        let diff = (ts - hello_ts) * 1000.0;
        diff.abs() as u64
    });

    // Is this packet within the injection_window after ClientHello?
    // Used for evidence (delta_ms field in signal output).
    let within_injection_window =
        delta_ms_from_hello.is_some_and(|d| d <= config.detection.injection.injection_window);

    // For "server → client" packets, the server IP is in src (not dst).
    // We flip to report the server as dst_ip in our signal output.
    let dst_ip = pkt.src_ip.to_string();
    let dst_port = pkt.src_port;
    let sni = flow.sni.clone();

    // Check which type of suspicious packet this is:
    //   - RST flag set → possible RST injection
    //   - FIN flag set (no RST) → possible FIN injection
    //   - Window=0 or 1 (no SYN, no RST, no FIN) → possible window manipulation
    match (
        pkt.tcp_flags.has_rst(),
        pkt.tcp_flags.has_fin(),
        pkt.tcp_window <= 1 && !pkt.tcp_flags.has_syn(),
    ) {
        // ─── RST INJECTION ─────────────────────────────────────────
        // Most common DPI technique in Russia.
        // TSPU sends RST (often with ttl=52) to kill the TLS handshake.
        (true, _, _) => {
            // Two independent detection criteria (either one is sufficient):
            //
            // Criterion 1: TTL anomaly
            //   RST packet TTL differs from the real server's baseline.
            //   Strong evidence, but fails when TSPU and server have similar TTL
            //   (e.g. Cloudflare PoP in Moscow: TTL≈53, TSPU TTL=52, delta=1).
            //
            // Criterion 2: Timing-only (≤50ms post-hello, no server data)
            //   TSPU responds in 0-5ms (it's inline on the path).
            //   Legitimate RST (connection refused, overload) takes 50-200ms+.
            //   50ms threshold is conservative to avoid FP on fast servers.
            //   Requires post-hello context to avoid triggering on port scans.
            const TIMING_ONLY_THRESHOLD_MS: u64 = 50;
            let timing_injection = post_hello_no_data
                && delta_ms_from_hello.is_some_and(|d| d <= TIMING_ONLY_THRESHOLD_MS);

            if !has_ttl_anomaly && !timing_injection {
                return None;
            }

            // Include delta_ms in evidence if within injection_window (for context).
            let delta_ms = if within_injection_window {
                delta_ms_from_hello.unwrap_or(0)
            } else {
                0
            };

            Some(Signal::RstInjection {
                ts,
                dst_ip,
                dst_port,
                sni,
                ttl_expected: baseline,
                ttl_actual: pkt.ttl,
                delta_ms,
                salvo_count: flow.rst_salvo_count,
            })
        }

        // ─── FIN INJECTION ─────────────────────────────────────────
        // Rare in Russia (more common with China's GFW).
        // TSPU sends FIN instead of RST to gracefully close the connection.
        // Requires BOTH TTL anomaly AND post-hello context because legitimate
        // FINs are very common (normal connection teardown).
        (false, true, _) => {
            if !has_ttl_anomaly {
                return None;
            }
            // Only suspicious if ClientHello was sent but no server data arrived.
            // A FIN during normal data transfer with TTL anomaly is usually
            // CDN/load-balancer routing change, not DPI.
            if !post_hello_no_data {
                return None;
            }
            Some(Signal::FinInjection {
                ts,
                dst_ip,
                dst_port,
                sni,
                ttl_expected: baseline,
                ttl_actual: pkt.ttl,
            })
        }

        // ─── WINDOW MANIPULATION ───────────────────────────────────
        // DPI sets TCP window to 0 or 1 to throttle the connection.
        // Observed in Iran, not commonly seen in Russia.
        // Requires TTL anomaly (window=0 can happen legitimately under load).
        (false, false, true) => {
            if !has_ttl_anomaly {
                return None;
            }
            Some(Signal::WindowManipulation {
                ts,
                dst_ip,
                dst_port,
                sni,
                ttl_expected: baseline,
                ttl_actual: pkt.ttl,
                window_value: pkt.tcp_window,
            })
        }

        // Not a suspicious packet type (normal ACK, data, etc.)
        _ => None,
    }
}
