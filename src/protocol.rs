use serde::Serialize;
use std::io::{self, Write};

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Payload {
    State(StatePayload),
    Data(DataPayload),
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StatePayload {
    Alive { version: String },
    Degraded { reason: String },
    Fatal { reason: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DataPayload {
    Signal(SignalPayload),
    Gauge(GaugePayload),
}

#[derive(Debug, Clone, Serialize)]
pub struct SignalPayload {
    pub signal_type: AlertSignalType,
    pub fields: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AlertSignalType {
    RstInjection,
    IpBlackhole,
    DomainRedirected,
    ThrottleDetected,
    TlsInterference,
}

#[derive(Debug, Clone, Serialize)]
pub struct GaugePayload {
    pub packets: u64,
    pub flows: u64,
    pub signals: u64,
    pub elapsed_secs: f64,
}

// Convenience constructors (replace old functions)
pub fn state_alive(version: &str) -> Payload {
    Payload::State(StatePayload::Alive {
        version: version.to_string(),
    })
}

pub fn state_fatal(reason: &str) -> Payload {
    Payload::State(StatePayload::Fatal {
        reason: reason.to_string(),
    })
}

pub fn state_degraded(reason: &str) -> Payload {
    Payload::State(StatePayload::Degraded {
        reason: reason.to_string(),
    })
}

pub fn data_gauge(packets: u64, flows: u64, signals: u64, elapsed_secs: f64) -> Payload {
    Payload::Data(DataPayload::Gauge(GaugePayload {
        packets,
        flows,
        signals,
        elapsed_secs,
    }))
}

pub fn data_signal(signal_type: AlertSignalType, fields: serde_json::Value) -> Payload {
    Payload::Data(DataPayload::Signal(SignalPayload {
        signal_type,
        fields,
    }))
}

pub fn emit(payload: &Payload) {
    if let Ok(json) = serde_json::to_string(payload) {
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        let _ = writeln!(lock, "{json}");
        let _ = lock.flush();
    }
}

// Legacy compatibility — emit raw string (for non-protocol messages)
pub fn emit_raw(message: &str) {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{message}");
    let _ = lock.flush();
}
