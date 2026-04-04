//! Time-based drop/blackhole detector.
//!
//! Runs on a periodic timer (every 5 seconds) and checks for flows that
//! have been silent for too long. Unlike injection.rs which fires on individual
//! packets, this detector fires on the *absence* of expected responses.
//!
//! Two signal types:
//!
//! ```text
//!   IP_BLACKHOLE — SYN sent, no SYN-ACK received, SYN retransmits observed.
//!                  Indicates IP-level blocking (e.g. Meta/Facebook IPs in Russia).
//!                  Requires retransmit_count ≥ 1 to avoid false positives on
//!                  fresh flows that just haven't received SYN-ACK yet.
//!
//!   SILENT_DROP  — TCP connected, ClientHello sent, server went silent.
//!                  Indicates SNI-based blocking where TSPU drops packets instead
//!                  of injecting RST. Observed on discord.com (Russia, 2026-04).
//!                  Requires post_hello_timeout (15s) to avoid FP on slow servers.
//! ```
//!
//! Both signals fire at most once per flow (timeout_signal_fired flag).
//! Both skip private/loopback IPs (container-internal traffic).

use crate::config::Config;
use crate::flow::{is_private_ip, FlowKey, FlowPhase, FlowState};
use crate::signal::Signal;

/// Check a single flow for drop/blackhole conditions.
///
/// Called from `collect_timeout_signals()` in main.rs for every active flow.
/// Returns Some(Signal) if the flow looks like it's being dropped by DPI.
pub fn detect_timeout(
    flow: &FlowState,
    key: &FlowKey,
    config: &Config,
    now: f64,
) -> Option<Signal> {
    // Skip internal container traffic:
    //   - 10.99.0.x = bridge subnet (tinyproxy ↔ flowsense)
    //   - 172.17.0.x = docker bridge gateway
    //   - 192.168.x.x, 127.x.x.x = other private/loopback
    if is_private_ip(key.dst_ip) {
        return None;
    }

    // Fire-once: once we've emitted a timeout signal for this flow, don't repeat.
    // Without this, SILENT_DROP would fire every 5 seconds on the same stuck flow.
    // The flag is set by main.rs via FlowTable::mark_signal_fired() after emission.
    if flow.timeout_signal_fired {
        return None;
    }

    match flow.phase {
        // ─── IP_BLACKHOLE ──────────────────────────────────────────
        // Flow stuck in SynSent: SYN was sent but no SYN-ACK came back.
        //
        // Common cause: destination IP is blocked at routing level (not DPI).
        // Example: Meta/Facebook IPs are blackholed in Russia.
        //
        // Requires retransmit_count ≥ 1 because:
        //   - A fresh flow (just sent SYN, SYN-ACK in flight) would be a false positive
        //   - TCP stack retransmits SYN after ~1-3 seconds if no reply
        //   - Seeing at least one retransmit confirms the connection is actually stuck
        //
        // Note: SYN retransmits are tracked in flow.rs — each duplicate SYN
        // while in SynSent phase increments retransmit_count.
        FlowPhase::SynSent => {
            let elapsed = now - flow.syn_ts;
            match elapsed >= config.detection.drop.syn_timeout && flow.retransmit_count >= 1 {
                true => Some(Signal::IpBlackhole {
                    ts: now,
                    dst_ip: key.dst_ip.to_string(),
                    dst_port: key.dst_port,
                    syn_retransmits: flow.retransmit_count,
                }),
                false => None,
            }
        }

        // ─── SILENT_DROP ───────────────────────────────────────────
        // Flow in Established: TCP handshake completed (SYN-ACK received),
        // ClientHello was sent, but server never responded with data.
        //
        // This is a different blocking strategy from RST injection:
        // instead of actively killing the connection, TSPU silently drops
        // all packets after ClientHello containing the blocked SNI.
        //
        // Conditions:
        //   - has_client_hello = true (we sent TLS ClientHello)
        //   - bytes_rx == 0 (server never sent any data back)
        //   - rst_salvo_count == 0 (no RST seen — otherwise RST_INJECTION handles it)
        //   - elapsed since hello ≥ post_hello_timeout (15s, generous to avoid slow-server FP)
        //
        // The retransmit_count in the output shows how many times the TCP stack
        // retransmitted ClientHello — useful evidence (discord.com shows 5-7 retransmits).
        //
        // Known gotcha: client_hello_ts is set only on the FIRST ClientHello.
        // TCP retransmits of ClientHello increment retransmit_count instead of
        // resetting the timer. Without this fix, the timer would never expire
        // because retransmits kept pushing hello_ts forward.
        FlowPhase::Established => {
            let hello_ts = flow.client_hello_ts?;
            match flow.has_client_hello
                && flow.bytes_rx == 0
                && flow.rst_salvo_count == 0
                && (now - hello_ts) >= config.detection.drop.post_hello_timeout
            {
                true => Some(Signal::SilentDrop {
                    ts: now,
                    dst_ip: key.dst_ip.to_string(),
                    dst_port: key.dst_port,
                    sni: flow.sni.clone(),
                    retransmit_count: flow.retransmit_count,
                }),
                false => None,
            }
        }

        // Transferring or Finished — data is flowing or connection is done,
        // no drop detection needed.
        _ => None,
    }
}
