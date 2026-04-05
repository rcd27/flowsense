use flowsense::protocol::*;

#[test]
fn alive_message_format() {
    let payload = state_alive("0.2.0");
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "state");
    assert_eq!(parsed["kind"], "alive");
    assert_eq!(parsed["version"], "0.2.0");
    assert!(!json.contains('\n'));
}

#[test]
fn fatal_message_format() {
    let payload = state_fatal("AF_PACKET socket failed");
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "state");
    assert_eq!(parsed["kind"], "fatal");
    assert_eq!(parsed["reason"], "AF_PACKET socket failed");
}

#[test]
fn gauge_message_format() {
    let payload = data_gauge(125432, 87, 42, 123.5);
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "data");
    assert_eq!(parsed["kind"], "gauge");
    assert_eq!(parsed["packets"], 125432);
}

#[test]
fn signal_message_format() {
    let fields = serde_json::json!({"dst_ip": "1.2.3.4", "dst_port": 443});
    let payload = data_signal(AlertSignalType::RstInjection, fields);
    let json = serde_json::to_string(&payload).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["type"], "data");
    assert_eq!(parsed["kind"], "signal");
    assert_eq!(parsed["signal_type"], "RST_INJECTION");
}

#[test]
fn all_messages_have_type_discriminator() {
    let messages: Vec<Payload> = vec![
        state_alive("0.2.0"),
        state_fatal("error"),
        state_degraded("warning"),
        data_gauge(100, 50, 10, 60.0),
        data_signal(AlertSignalType::IpBlackhole, serde_json::json!({})),
    ];
    for payload in &messages {
        let json = serde_json::to_string(payload).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("type").is_some(), "must have 'type' field: {json}");
    }
}
