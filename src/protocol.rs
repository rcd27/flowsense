use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

// --- State messages ---

#[derive(Serialize)]
struct StateAlive<'a> {
    state: &'static str,
    version: &'a str,
}

#[derive(Serialize)]
struct StateFatal<'a> {
    state: &'static str,
    reason: &'a str,
}

pub fn state_alive(version: &str) -> String {
    serde_json::to_string(&StateAlive {
        state: "alive",
        version,
    })
    .unwrap()
}

pub fn state_fatal(reason: &str) -> String {
    serde_json::to_string(&StateFatal {
        state: "fatal",
        reason,
    })
    .unwrap()
}

// --- Data messages ---

#[derive(Serialize)]
struct DataGauge {
    data: &'static str,
    packets: u64,
    flows: u64,
    signals: u64,
    elapsed_secs: f64,
}

pub fn data_gauge(packets: u64, flows: u64, signals: u64, elapsed_secs: f64) -> String {
    serde_json::to_string(&DataGauge {
        data: "gauge",
        packets,
        flows,
        signals,
        elapsed_secs,
    })
    .unwrap()
}

/// Оборачивает существующий flowsense signal JSON в Component Protocol envelope:
/// {"signal":"RST_INJECTION","evidence":{...}}
///   → {"data":"signal","name":"RST_INJECTION","evidence":{...}}
pub fn wrap_signal(signal_json: &str) -> String {
    let mut parsed: Value = match serde_json::from_str(signal_json) {
        Ok(v) => v,
        Err(_) => return signal_json.to_string(),
    };

    let obj = match parsed.as_object_mut() {
        Some(o) => o,
        None => return signal_json.to_string(),
    };

    let name = match obj.remove("signal") {
        Some(Value::String(s)) => s,
        _ => return signal_json.to_string(),
    };

    let mut envelope = serde_json::Map::new();
    envelope.insert("data".into(), Value::String("signal".into()));
    envelope.insert("name".into(), Value::String(name));

    for (k, v) in obj.iter() {
        envelope.insert(k.clone(), v.clone());
    }

    serde_json::to_string(&envelope).unwrap()
}

pub fn emit(message: &str) {
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{}", message);
    let _ = lock.flush();
}
