use flowsense::protocol::{data_gauge, state_alive, state_fatal, wrap_signal};

// --- State messages ---

#[test]
fn alive_message_format() {
    let json = state_alive("0.2.0");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["state"], "alive");
    assert_eq!(parsed["version"], "0.2.0");
    assert!(!json.contains('\n'));
}

#[test]
fn fatal_message_format() {
    let json = state_fatal("AF_PACKET socket failed: permission denied");
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["state"], "fatal");
    assert_eq!(parsed["reason"], "AF_PACKET socket failed: permission denied");
}

// --- Data messages ---

#[test]
fn gauge_message_format() {
    let json = data_gauge(125432, 87, 42, 123.5);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["data"], "gauge");
    assert_eq!(parsed["packets"], 125432);
    assert_eq!(parsed["flows"], 87);
    assert_eq!(parsed["signals"], 42);
    assert_eq!(parsed["elapsed_secs"], 123.5);
}

#[test]
fn wrap_signal_adds_data_envelope() {
    let original =
        r#"{"signal":"RST_INJECTION","evidence":{"ts":123.0,"dst_ip":"1.2.3.4","dst_port":443}}"#;
    let wrapped = wrap_signal(original);
    let parsed: serde_json::Value = serde_json::from_str(&wrapped).unwrap();
    assert_eq!(parsed["data"], "signal");
    assert_eq!(parsed["name"], "RST_INJECTION");
    assert!(parsed["evidence"].is_object());
    assert!(!wrapped.contains('\n'));
}

#[test]
fn wrap_signal_preserves_all_evidence_fields() {
    let original = r#"{"signal":"IP_BLACKHOLE","evidence":{"ts":5.0,"dst_ip":"157.240.1.35","dst_port":443,"syn_retransmits":5}}"#;
    let wrapped = wrap_signal(original);
    let parsed: serde_json::Value = serde_json::from_str(&wrapped).unwrap();
    assert_eq!(parsed["name"], "IP_BLACKHOLE");
    assert_eq!(parsed["evidence"]["syn_retransmits"], 5);
}

// --- Protocol invariants ---

#[test]
fn all_messages_have_exactly_one_discriminator() {
    let original =
        r#"{"signal":"RST_INJECTION","evidence":{"ts":1.0,"dst_ip":"1.2.3.4","dst_port":443}}"#;

    let messages = vec![
        state_alive("0.2.0"),
        state_fatal("socket failed"),
        data_gauge(1000, 50, 10, 60.0),
        wrap_signal(original),
    ];

    for msg in &messages {
        let parsed: serde_json::Value = serde_json::from_str(msg).unwrap();
        let obj = parsed.as_object().unwrap();
        let has_state = obj.contains_key("state");
        let has_data = obj.contains_key("data");

        assert!(
            has_state ^ has_data,
            "must have exactly one of 'state' or 'data': {}",
            msg
        );
    }
}
