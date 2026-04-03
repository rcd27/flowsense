#[path = "helpers/mod.rs"]
mod helpers;

use std::net::Ipv4Addr;

use flowsense::config::{Config, FlowsConfig};
use flowsense::flow::{flow_key_from_packet, FlowPhase, FlowTable};
use flowsense::parser::parse;
use helpers::{build_tcp_packet, tls_client_hello, TcpFlag};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const CLIENT_PORT: u16 = 54321;

// PORT_LOW (< 1024): classify_direction → FromClient for non-SYN packets.
// Used to send ClientHello as FromClient.
const PORT_LOW: u16 = 443;

// PORT_HIGH (>= 1024): classify_direction → FromServer for non-SYN packets.
// Used to send server data / SYN-ACK as FromServer.
const PORT_HIGH: u16 = 8443;

fn make_table(flow_ttl: f64) -> FlowTable {
    let mut cfg = Config::default();
    cfg.flows = FlowsConfig {
        flow_ttl,
        max_flows: 1000,
    };
    FlowTable::new(cfg.flows)
}

#[test]
fn test_syn_creates_flow_in_syn_sent() {
    let mut table = make_table(120.0);

    let frame = build_tcp_packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_LOW,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let pkt = parse(&frame).expect("parse");
    table.update(&pkt, 1.0);

    assert_eq!(table.len(), 1);
    let key = flow_key_from_packet(&pkt);
    let state = table.get(&key).expect("flow must exist");
    assert_eq!(state.phase, FlowPhase::SynSent);
    assert_eq!(state.syn_ts, 1.0);
    assert!(state.ttl_baseline.is_none());
}

#[test]
fn test_syn_ack_transitions_to_established_and_records_ttl() {
    let mut table = make_table(120.0);

    // SYN: key = {SERVER_IP, PORT_LOW}
    let syn_frame = build_tcp_packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_LOW,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let syn_pkt = parse(&syn_frame).expect("parse syn");
    table.update(&syn_pkt, 1.0);

    // SYN-ACK with same flow key (dst=SERVER_IP, dst_port=PORT_LOW).
    // flow.rs handles SYN_ACK independent of direction.
    let syn_ack_frame = build_tcp_packet(
        SERVER_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_LOW,
        56,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let syn_ack_pkt = parse(&syn_ack_frame).expect("parse syn_ack");
    table.update(&syn_ack_pkt, 1.5);

    let key = flow_key_from_packet(&syn_pkt);
    let state = table.get(&key).expect("flow must exist");
    assert_eq!(state.phase, FlowPhase::Established);
    assert_eq!(state.ttl_baseline, Some(56));
}

#[test]
fn test_client_hello_records_sni() {
    let mut table = make_table(120.0);

    // SYN: key = {SERVER_IP, PORT_LOW}
    let syn_frame = build_tcp_packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_LOW,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let syn_pkt = parse(&syn_frame).expect("parse syn");
    table.update(&syn_pkt, 1.0);

    // SYN-ACK → Established
    let syn_ack_frame = build_tcp_packet(
        SERVER_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_LOW,
        56,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let syn_ack_pkt = parse(&syn_ack_frame).expect("parse syn_ack");
    table.update(&syn_ack_pkt, 1.5);

    // ClientHello: dst_port=PORT_LOW(443) < 1024 → FromClient ✓
    let hello_payload = tls_client_hello("example.com");
    let hello_frame = build_tcp_packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_LOW,
        64,
        TcpFlag::PshAck,
        1001,
        2001,
        65535,
        &hello_payload,
    );
    let hello_pkt = parse(&hello_frame).expect("parse hello");
    table.update(&hello_pkt, 2.0);

    let key = flow_key_from_packet(&syn_pkt);
    let state = table.get(&key).expect("flow must exist");
    assert!(state.has_client_hello);
    assert_eq!(state.sni.as_deref(), Some("example.com"));
    assert_eq!(state.client_hello_ts, Some(2.0));
}

#[test]
fn test_data_transitions_to_transferring() {
    let mut table = make_table(120.0);

    // SYN: key = {SERVER_IP, PORT_HIGH}
    let syn_frame = build_tcp_packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_HIGH,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let syn_pkt = parse(&syn_frame).expect("parse syn");
    table.update(&syn_pkt, 1.0);

    // SYN-ACK → Established
    let syn_ack_frame = build_tcp_packet(
        SERVER_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_HIGH,
        56,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let syn_ack_pkt = parse(&syn_ack_frame).expect("parse syn_ack");
    table.update(&syn_ack_pkt, 1.5);

    // Server data: dst_port=PORT_HIGH(8443) >= 1024 → FromServer ✓
    let data = vec![0xabu8; 1400];
    let data_frame = build_tcp_packet(
        SERVER_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_HIGH,
        56,
        TcpFlag::PshAck,
        3000,
        1001,
        65535,
        &data,
    );
    let data_pkt = parse(&data_frame).expect("parse data");
    table.update(&data_pkt, 2.0);

    let key = flow_key_from_packet(&syn_pkt);
    let state = table.get(&key).expect("flow must exist");
    assert_eq!(state.phase, FlowPhase::Transferring);
    assert_eq!(state.bytes_rx, 1400);
}

#[test]
fn test_flow_expiry() {
    let mut table = make_table(0.0);

    let frame = build_tcp_packet(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        PORT_LOW,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let pkt = parse(&frame).expect("parse");
    table.update(&pkt, 1.0);

    assert_eq!(table.len(), 1);

    // flow_ttl=0.0: retain condition is now - last_activity_ts < 0.0, always false → all expire.
    table.expire(2.0);

    assert_eq!(table.len(), 0);
}
