use crate::config::Config;
use crate::flow::{FlowKey, FlowPhase, FlowState};
use crate::signal::Signal;

pub fn detect_cliff(flow: &FlowState, key: &FlowKey, config: &Config, now: f64) -> Option<Signal> {
    let cfg = &config.detection.throughput;

    (flow.phase == FlowPhase::Transferring)
        .then(|| flow.last_data_ts)
        .flatten()
        .and_then(|last_data| {
            let stall = now - last_data;
            let cliff_condition = stall >= cfg.cliff_timeout
                && flow.bytes_rx > 0
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

pub fn detect_retransmit(
    flow: &FlowState,
    key: &FlowKey,
    config: &Config,
    now: f64,
) -> Option<Signal> {
    let cfg = &config.detection.throughput;

    (flow.phase == FlowPhase::Transferring)
        .then(|| flow.first_data_ts)
        .flatten()
        .and_then(|first_data| {
            let window = now - first_data;
            let total_packets = flow.server_retransmit_count + 1;
            let ratio = flow.server_retransmit_count as f64 / total_packets as f64;
            let condition = window >= cfg.throttle_window
                && total_packets >= 5
                && ratio >= cfg.retransmit_ratio;
            condition.then(|| {
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

pub fn detect_ack_drop(
    flow: &FlowState,
    key: &FlowKey,
    config: &Config,
    now: f64,
) -> Option<Signal> {
    let cfg = &config.detection.throughput;

    let total_packets = flow.server_retransmit_count + 1;
    let ratio = flow.server_retransmit_count as f64 / total_packets as f64;

    let condition = flow.phase == FlowPhase::Transferring
        && flow.server_retransmit_count > 5
        && flow.bytes_tx > 0
        && ratio >= cfg.retransmit_ratio;

    condition.then(|| Signal::AckDrop {
        ts: now,
        dst_ip: key.dst_ip.to_string(),
        dst_port: key.dst_port,
        sni: flow.sni.clone(),
        server_retransmits: flow.server_retransmit_count,
    })
}
