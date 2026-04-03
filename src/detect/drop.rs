use crate::config::Config;
use crate::flow::{FlowKey, FlowPhase, FlowState};
use crate::signal::Signal;

pub fn detect_timeout(
    flow: &FlowState,
    key: &FlowKey,
    config: &Config,
    now: f64,
) -> Option<Signal> {
    match flow.phase {
        FlowPhase::SynSent => {
            let elapsed = now - flow.syn_ts;
            match elapsed >= config.detection.drop.syn_timeout {
                true => Some(Signal::IpBlackhole {
                    ts: now,
                    dst_ip: key.dst_ip.to_string(),
                    dst_port: key.dst_port,
                    syn_retransmits: flow.retransmit_count,
                }),
                false => None,
            }
        }

        FlowPhase::Established => {
            let hello_ts = flow.client_hello_ts?;
            match flow.has_client_hello
                && flow.bytes_rx == 0
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

        _ => None,
    }
}
