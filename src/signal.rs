use serde::{Deserialize, Serialize};

use crate::protocol::AlertSignalType;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "signal", content = "evidence")]
pub enum Signal {
    RstInjection {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        ttl_expected: u8,
        ttl_actual: u8,
        delta_ms: u64,
        salvo_count: u32,
    },
    FinInjection {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        ttl_expected: u8,
        ttl_actual: u8,
    },
    WindowManipulation {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        ttl_expected: u8,
        ttl_actual: u8,
        window_value: u16,
    },
    DnsPoisoning {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        ttl_first: u8,
        ttl_second: u8,
        answer_first: String,
        answer_second: String,
    },
    HttpRedirectInjection {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        ttl_expected: u8,
        ttl_actual: u8,
        redirect_target: String,
    },
    IpBlackhole {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        syn_retransmits: u32,
    },
    SilentDrop {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        retransmit_count: u32,
    },
    ThrottleCliff {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        bytes_before_cliff: u64,
        stall_duration: f64,
    },
    ThrottleProbabilistic {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        retransmit_ratio: f64,
        throughput_bps: f64,
        server_retransmits: u32,
    },
    AckDrop {
        ts: f64,
        dst_ip: String,
        dst_port: u16,
        sni: Option<String>,
        server_retransmits: u32,
    },
}

impl Signal {
    pub fn ts(&self) -> f64 {
        match self {
            Signal::RstInjection { ts, .. } => *ts,
            Signal::FinInjection { ts, .. } => *ts,
            Signal::WindowManipulation { ts, .. } => *ts,
            Signal::DnsPoisoning { ts, .. } => *ts,
            Signal::HttpRedirectInjection { ts, .. } => *ts,
            Signal::IpBlackhole { ts, .. } => *ts,
            Signal::SilentDrop { ts, .. } => *ts,
            Signal::ThrottleCliff { ts, .. } => *ts,
            Signal::ThrottleProbabilistic { ts, .. } => *ts,
            Signal::AckDrop { ts, .. } => *ts,
        }
    }

    pub fn dst_ip(&self) -> &str {
        match self {
            Signal::RstInjection { dst_ip, .. } => dst_ip,
            Signal::FinInjection { dst_ip, .. } => dst_ip,
            Signal::WindowManipulation { dst_ip, .. } => dst_ip,
            Signal::DnsPoisoning { dst_ip, .. } => dst_ip,
            Signal::HttpRedirectInjection { dst_ip, .. } => dst_ip,
            Signal::IpBlackhole { dst_ip, .. } => dst_ip,
            Signal::SilentDrop { dst_ip, .. } => dst_ip,
            Signal::ThrottleCliff { dst_ip, .. } => dst_ip,
            Signal::ThrottleProbabilistic { dst_ip, .. } => dst_ip,
            Signal::AckDrop { dst_ip, .. } => dst_ip,
        }
    }

    pub fn dst_port(&self) -> u16 {
        match self {
            Signal::RstInjection { dst_port, .. } => *dst_port,
            Signal::FinInjection { dst_port, .. } => *dst_port,
            Signal::WindowManipulation { dst_port, .. } => *dst_port,
            Signal::DnsPoisoning { dst_port, .. } => *dst_port,
            Signal::HttpRedirectInjection { dst_port, .. } => *dst_port,
            Signal::IpBlackhole { dst_port, .. } => *dst_port,
            Signal::SilentDrop { dst_port, .. } => *dst_port,
            Signal::ThrottleCliff { dst_port, .. } => *dst_port,
            Signal::ThrottleProbabilistic { dst_port, .. } => *dst_port,
            Signal::AckDrop { dst_port, .. } => *dst_port,
        }
    }

    pub fn alert_signal_type(&self) -> AlertSignalType {
        match self {
            Signal::RstInjection { .. } => AlertSignalType::RstInjection,
            Signal::FinInjection { .. } => AlertSignalType::TlsInterference,
            Signal::WindowManipulation { .. } => AlertSignalType::TlsInterference,
            Signal::DnsPoisoning { .. } => AlertSignalType::TlsInterference,
            Signal::HttpRedirectInjection { .. } => AlertSignalType::TlsInterference,
            Signal::IpBlackhole { .. } => AlertSignalType::IpBlackhole,
            Signal::SilentDrop { .. } => AlertSignalType::IpBlackhole,
            Signal::ThrottleCliff { .. } => AlertSignalType::ThrottleDetected,
            Signal::ThrottleProbabilistic { .. } => AlertSignalType::ThrottleDetected,
            Signal::AckDrop { .. } => AlertSignalType::ThrottleDetected,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Signal::RstInjection { .. } => "RST_INJECTION",
            Signal::FinInjection { .. } => "FIN_INJECTION",
            Signal::WindowManipulation { .. } => "WINDOW_MANIPULATION",
            Signal::DnsPoisoning { .. } => "DNS_POISONING",
            Signal::HttpRedirectInjection { .. } => "HTTP_REDIRECT_INJECTION",
            Signal::IpBlackhole { .. } => "IP_BLACKHOLE",
            Signal::SilentDrop { .. } => "SILENT_DROP",
            Signal::ThrottleCliff { .. } => "THROTTLE_CLIFF",
            Signal::ThrottleProbabilistic { .. } => "THROTTLE_PROBABILISTIC",
            Signal::AckDrop { .. } => "ACK_DROP",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_name_rst_injection() {
        let s = Signal::RstInjection {
            ts: 0.0,
            dst_ip: "1.2.3.4".to_string(),
            dst_port: 443,
            sni: None,
            ttl_expected: 52,
            ttl_actual: 61,
            delta_ms: 12,
            salvo_count: 3,
        };
        assert_eq!(s.name(), "RST_INJECTION");
        assert_eq!(s.dst_port(), 443);
        assert_eq!(s.dst_ip(), "1.2.3.4");
    }

    #[test]
    fn alert_signal_type_mapping() {
        let rst = Signal::RstInjection { ts: 0.0, dst_ip: "1.2.3.4".into(), dst_port: 443, sni: None, ttl_expected: 52, ttl_actual: 61, delta_ms: 12, salvo_count: 3 };
        assert_eq!(rst.alert_signal_type(), AlertSignalType::RstInjection);

        let blackhole = Signal::IpBlackhole { ts: 0.0, dst_ip: "1.2.3.4".into(), dst_port: 443, syn_retransmits: 5 };
        assert_eq!(blackhole.alert_signal_type(), AlertSignalType::IpBlackhole);

        let silent = Signal::SilentDrop { ts: 0.0, dst_ip: "1.2.3.4".into(), dst_port: 443, sni: None, retransmit_count: 3 };
        assert_eq!(silent.alert_signal_type(), AlertSignalType::IpBlackhole);

        let throttle = Signal::ThrottleCliff { ts: 0.0, dst_ip: "1.2.3.4".into(), dst_port: 443, sni: None, bytes_before_cliff: 1000, stall_duration: 3.0 };
        assert_eq!(throttle.alert_signal_type(), AlertSignalType::ThrottleDetected);
    }

    #[test]
    fn signal_serialization_roundtrip() {
        let s = Signal::DnsPoisoning {
            ts: 1.5,
            dst_ip: "8.8.8.8".to_string(),
            dst_port: 53,
            ttl_first: 64,
            ttl_second: 128,
            answer_first: "1.2.3.4".to_string(),
            answer_second: "5.6.7.8".to_string(),
        };
        let json = serde_json::to_string(&s).expect("serialize");
        let back: Signal = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.name(), "DNS_POISONING");
    }
}
