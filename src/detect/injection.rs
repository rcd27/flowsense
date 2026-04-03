use crate::config::Config;
use crate::flow::FlowState;
use crate::parser::ParsedPacket;
use crate::signal::Signal;

fn ttl_anomaly(actual: u8, baseline: u8, tolerance: u8) -> Option<u8> {
    let delta = actual.abs_diff(baseline);
    match delta > tolerance {
        true => Some(delta),
        false => None,
    }
}

pub fn detect(pkt: &ParsedPacket, flow: &FlowState, config: &Config, ts: f64) -> Option<Signal> {
    let baseline = flow.ttl_baseline?;
    let tolerance = config.detection.injection.ttl_tolerance;
    let _delta = ttl_anomaly(pkt.ttl, baseline, tolerance)?;

    let dst_ip = pkt.dst_ip.to_string();
    let dst_port = pkt.dst_port;
    let sni = flow.sni.clone();

    match (
        pkt.tcp_flags.has_rst(),
        pkt.tcp_flags.has_fin(),
        pkt.tcp_window <= 1 && !pkt.tcp_flags.has_syn(),
    ) {
        (true, _, _) => {
            let delta_ms = flow
                .client_hello_ts
                .map(|hello_ts| {
                    let diff = (ts - hello_ts) * 1000.0;
                    diff.abs() as u64
                })
                .filter(|&d| d <= config.detection.injection.injection_window)
                .unwrap_or(0);

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
        (false, true, _) => Some(Signal::FinInjection {
            ts,
            dst_ip,
            dst_port,
            sni,
            ttl_expected: baseline,
            ttl_actual: pkt.ttl,
        }),
        (false, false, true) => Some(Signal::WindowManipulation {
            ts,
            dst_ip,
            dst_port,
            sni,
            ttl_expected: baseline,
            ttl_actual: pkt.ttl,
            window_value: pkt.tcp_window,
        }),
        _ => None,
    }
}
