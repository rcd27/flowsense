use crate::signal::Signal;
use serde_json::Value;

pub fn format_json(signal: &Signal) -> String {
    let mut value = match serde_json::to_value(signal) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    // Replace the serde variant name (e.g. "RstInjection") with the canonical
    // screaming-snake name (e.g. "RST_INJECTION") so consumers get a stable key.
    if let Value::Object(ref mut map) = value {
        if let Some(tag) = map.get_mut("signal") {
            *tag = Value::String(signal.name().to_string());
        }
    }
    serde_json::to_string(&value).unwrap_or_default()
}

pub fn format_human(signal: &Signal) -> String {
    let ts = format_ts(signal.ts());
    let addr = format!("{}:{}", signal.dst_ip(), signal.dst_port());
    let name = signal.name();
    let details = format_details(signal);
    format!("[{}] {:<24}{:<24}{}", ts, addr, name, details)
}

fn format_ts(ts: f64) -> String {
    let total_secs = ts as u64;
    let h = total_secs / 3600;
    let m = (total_secs % 3600) / 60;
    let s = total_secs % 60;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

fn format_details(signal: &Signal) -> String {
    match signal {
        Signal::RstInjection {
            ttl_expected,
            ttl_actual,
            salvo_count,
            delta_ms,
            ..
        } => format!(
            "ttl={}→{} salvo={} after_hello={}ms",
            ttl_expected, ttl_actual, salvo_count, delta_ms
        ),
        Signal::FinInjection {
            ttl_expected,
            ttl_actual,
            ..
        } => format!("ttl={}→{}", ttl_expected, ttl_actual),
        Signal::WindowManipulation {
            ttl_expected,
            ttl_actual,
            window_value,
            ..
        } => format!(
            "ttl={}→{} window={}",
            ttl_expected, ttl_actual, window_value
        ),
        Signal::DnsPoisoning {
            ttl_first,
            ttl_second,
            answer_first,
            answer_second,
            ..
        } => format!(
            "ttl={}→{} answers={}|{}",
            ttl_first, ttl_second, answer_first, answer_second
        ),
        Signal::HttpRedirectInjection {
            ttl_expected,
            ttl_actual,
            redirect_target,
            ..
        } => format!(
            "ttl={}→{} redirect={}",
            ttl_expected, ttl_actual, redirect_target
        ),
        Signal::IpBlackhole {
            syn_retransmits, ..
        } => {
            format!("syn_retransmits={}", syn_retransmits)
        }
        Signal::SilentDrop {
            retransmit_count, ..
        } => format!("retransmits={} post_hello", retransmit_count),
        Signal::ThrottleCliff {
            bytes_before_cliff,
            stall_duration,
            ..
        } => format!("bytes={} stall={:.1}s", bytes_before_cliff, stall_duration),
        Signal::ThrottleProbabilistic {
            retransmit_ratio,
            throughput_bps,
            ..
        } => format!(
            "retransmit={:.0}% throughput={:.0}bps",
            retransmit_ratio * 100.0,
            throughput_bps
        ),
        Signal::AckDrop {
            server_retransmits, ..
        } => format!("server_retransmits={} asymmetric=true", server_retransmits),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::Signal;

    #[test]
    fn test_json_output_contains_signal_name() {
        let signal = Signal::RstInjection {
            ts: 3661.0,
            dst_ip: "discord.com".to_string(),
            dst_port: 443,
            sni: Some("discord.com".to_string()),
            ttl_expected: 52,
            ttl_actual: 61,
            delta_ms: 12,
            salvo_count: 3,
        };
        let json = format_json(&signal);
        assert!(
            json.contains("RST_INJECTION"),
            "JSON should contain RST_INJECTION, got: {}",
            json
        );
        assert!(
            json.contains("discord.com"),
            "JSON should contain discord.com, got: {}",
            json
        );
        assert!(
            !json.contains('\n'),
            "JSON should be single line, got: {}",
            json
        );
    }

    #[test]
    fn test_human_output_format() {
        let signal = Signal::ThrottleCliff {
            ts: 0.0,
            dst_ip: "1.2.3.4".to_string(),
            dst_port: 443,
            sni: None,
            bytes_before_cliff: 16384,
            stall_duration: 3.2,
        };
        let human = format_human(&signal);
        assert!(
            human.contains("THROTTLE_CLIFF"),
            "output should contain THROTTLE_CLIFF, got: {}",
            human
        );
        assert!(
            human.contains("bytes=16384"),
            "output should contain bytes=16384, got: {}",
            human
        );
        assert!(
            human.contains("stall=3.2s"),
            "output should contain stall=3.2s, got: {}",
            human
        );
    }
}
