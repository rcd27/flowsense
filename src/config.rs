use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub snaplen: u32,
    pub promisc: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            snaplen: 128,
            promisc: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropConfig {
    pub syn_timeout: f64,
    pub post_hello_timeout: f64,
}

impl Default for DropConfig {
    fn default() -> Self {
        Self {
            syn_timeout: 5.0,
            post_hello_timeout: 10.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionConfig {
    pub ttl_tolerance: u8,
    pub injection_window: u64,
}

impl Default for InjectionConfig {
    fn default() -> Self {
        Self {
            ttl_tolerance: 2,
            injection_window: 500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThroughputConfig {
    pub cliff_threshold: u64,
    pub cliff_min_bytes: u64,
    pub cliff_timeout: f64,
    pub throttle_window: f64,
    pub retransmit_ratio: f64,
}

impl Default for ThroughputConfig {
    fn default() -> Self {
        Self {
            cliff_threshold: 20480,
            cliff_min_bytes: 4096,
            cliff_timeout: 3.0,
            throttle_window: 10.0,
            retransmit_ratio: 0.3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectionConfig {
    pub drop: DropConfig,
    pub injection: InjectionConfig,
    pub throughput: ThroughputConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowsConfig {
    pub flow_ttl: f64,
    pub max_flows: usize,
}

impl Default for FlowsConfig {
    fn default() -> Self {
        Self {
            flow_ttl: 120.0,
            max_flows: 50000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    pub capture: CaptureConfig,
    pub detection: DetectionConfig,
    pub flows: FlowsConfig,
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, io::Error> {
        let contents = fs::read_to_string(path)?;
        serde_json::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).expect("Config is always serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_serializes() {
        let cfg = Config::default();
        let json = cfg.to_json_pretty();
        assert!(json.contains("snaplen"));
        assert!(json.contains("promisc"));
        assert!(json.contains("syn_timeout"));
        assert!(json.contains("ttl_tolerance"));
        assert!(json.contains("cliff_threshold"));
        assert!(json.contains("flow_ttl"));
    }

    #[test]
    fn default_config_values() {
        let cfg = Config::default();
        assert_eq!(cfg.capture.snaplen, 128);
        assert!(cfg.capture.promisc);
        assert_eq!(cfg.detection.drop.syn_timeout, 5.0);
        assert_eq!(cfg.detection.drop.post_hello_timeout, 10.0);
        assert_eq!(cfg.detection.injection.ttl_tolerance, 2);
        assert_eq!(cfg.detection.injection.injection_window, 500);
        assert_eq!(cfg.detection.throughput.cliff_threshold, 20480);
        assert_eq!(cfg.detection.throughput.cliff_timeout, 3.0);
        assert_eq!(cfg.detection.throughput.throttle_window, 10.0);
        assert_eq!(cfg.detection.throughput.retransmit_ratio, 0.3);
        assert_eq!(cfg.flows.flow_ttl, 120.0);
        assert_eq!(cfg.flows.max_flows, 50000);
    }

    #[test]
    fn config_roundtrip() {
        let cfg = Config::default();
        let json = cfg.to_json_pretty();
        let back: Config = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.capture.snaplen, cfg.capture.snaplen);
        assert_eq!(back.flows.max_flows, cfg.flows.max_flows);
    }
}
