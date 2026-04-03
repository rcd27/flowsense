#[path = "helpers/mod.rs"]
mod helpers;

use std::net::Ipv4Addr;

use flowsense::config::Config;
use flowsense::detect::{drop, injection, throughput};
use flowsense::flow::{FlowKey, FlowTable};
use flowsense::parser::parse;
use helpers::{build_tcp_packet, tls_client_hello, TcpFlag};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const CLIENT_PORT: u16 = 54321;
const SERVER_PORT: u16 = 443;
// dst_port >= 1024 → classify_direction returns FromServer for non-SYN packets
const SERVER_PORT_HIGH: u16 = 8443;

/// Build an established flow with baseline TTL, return (table, hello_ts).
fn setup_established(baseline_ttl: u8) -> (FlowTable, f64) {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    // SYN from client
    let syn_frame = build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let syn_pkt = parse(&syn_frame).expect("parse syn");
    table.update(&syn_pkt, 1.0);

    // SYN-ACK from server with baseline TTL
    let syn_ack_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        baseline_ttl,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let syn_ack_pkt = parse(&syn_ack_frame).expect("parse syn_ack");
    table.update(&syn_ack_pkt, 1.5);

    // ClientHello with SNI
    let hello_payload = tls_client_hello("example.com");
    let hello_frame = build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        64,
        TcpFlag::PshAck,
        1001,
        2001,
        65535,
        &hello_payload,
    );
    let hello_pkt = parse(&hello_frame).expect("parse hello");
    table.update(&hello_pkt, 2.0);

    (table, 2.0)
}

#[test]
fn test_server_rst_with_normal_ttl_not_injection() {
    let config = Config::default();
    let (mut table, _hello_ts) = setup_established(52);

    // RST with TTL=52 (baseline=52, delta=0 ≤ tolerance=2) → should not trigger injection
    let rst_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        52,
        TcpFlag::Rst,
        3000,
        0,
        0,
        &[],
    );
    let rst_pkt = parse(&rst_frame).expect("parse rst");

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let result = injection::detect(&rst_pkt, flow, &config, 2.5);

    assert!(
        result.is_none(),
        "RST with matching TTL=52 must not trigger injection, got {:?}",
        result
    );
}

#[test]
fn test_ecmp_ttl_jitter_not_injection() {
    let config = Config::default();
    let (mut table, _hello_ts) = setup_established(52);

    // Data packet (PshAck) with TTL=54 (baseline=52, delta=2 = tolerance=2)
    // ttl_anomaly returns Some only when delta > tolerance, so delta==tolerance → None
    let data_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        54,
        TcpFlag::PshAck,
        3000,
        1001,
        65535,
        &[0xabu8; 100],
    );
    let data_pkt = parse(&data_frame).expect("parse data");

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let result = injection::detect(&data_pkt, flow, &config, 2.5);

    assert!(
        result.is_none(),
        "ECMP TTL jitter of delta=2 at tolerance=2 must not trigger injection, got {:?}",
        result
    );
}

#[test]
fn test_slow_server_not_silent_drop() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    // SYN at t=0
    let syn_frame = build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let syn_pkt = parse(&syn_frame).expect("parse syn");
    table.update(&syn_pkt, 0.0);

    // SYN-ACK at t=0.1
    let syn_ack_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        52,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let syn_ack_pkt = parse(&syn_ack_frame).expect("parse syn_ack");
    table.update(&syn_ack_pkt, 0.1);

    // ClientHello at t=0.2
    let hello_payload = tls_client_hello("example.com");
    let hello_frame = build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        64,
        TcpFlag::PshAck,
        1001,
        2001,
        65535,
        &hello_payload,
    );
    let hello_pkt = parse(&hello_frame).expect("parse hello");
    table.update(&hello_pkt, 0.2);

    // Server responds slowly at t=8.2 (slow but within post_hello_timeout=10s)
    // Use SERVER_PORT_HIGH so PshAck is classified as FromServer → bytes_rx > 0
    let response_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT_HIGH,
        52,
        TcpFlag::PshAck,
        3000,
        1001,
        65535,
        &[0xabu8; 200],
    );
    let response_pkt = parse(&response_frame).expect("parse server response");
    // Update using server_port_high key
    let mut table2 = FlowTable::new(config.flows.clone());
    table2.update(&syn_ack_pkt, 0.1);
    let _ = response_pkt; // unused in this flow

    // Check at t=9: now - hello_ts = 9 - 0.2 = 8.8 < post_hello_timeout=10 → None
    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let result = drop::detect_timeout(flow, &key, &config, 9.0);

    assert!(result.is_none(), "slow server at t=8.2 checked at t=9 (8.8s elapsed < 10s timeout) must not trigger SilentDrop, got {:?}", result);
}

#[test]
fn test_legitimate_fin_not_injection() {
    let config = Config::default();
    let (mut table, _hello_ts) = setup_established(52);

    // FIN with TTL=52 (matching baseline, delta=0 ≤ tolerance=2) → no injection
    let fin_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        52,
        TcpFlag::Fin,
        3000,
        0,
        65535,
        &[],
    );
    let fin_pkt = parse(&fin_frame).expect("parse fin");

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let result = injection::detect(&fin_pkt, flow, &config, 2.5);

    assert!(
        result.is_none(),
        "FIN with matching TTL=52 must not trigger injection, got {:?}",
        result
    );
}

#[test]
fn test_bursty_traffic_not_throttle() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    let mut ts = 1.0_f64;

    // SYN
    let syn_frame = build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT_HIGH,
        64,
        TcpFlag::Syn,
        1000,
        0,
        65535,
        &[],
    );
    let syn_pkt = parse(&syn_frame).expect("parse syn");
    table.update(&syn_pkt, ts);
    ts += 0.1;

    // SYN-ACK → Established
    let syn_ack_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT_HIGH,
        56,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let syn_ack_pkt = parse(&syn_ack_frame).expect("parse syn_ack");
    table.update(&syn_ack_pkt, ts);
    ts += 0.1;

    // Send 12 chunks of 1400 bytes → 16800 bytes total
    // bytes_rx=16800 ≤ cliff_threshold*2=40960, but pause < cliff_timeout=3 → None
    let mut seq: u32 = 3000;
    for _ in 0..12 {
        let data = vec![0xabu8; 1400];
        let data_frame = build_tcp_packet(
            SERVER,
            SERVER,
            CLIENT_PORT,
            SERVER_PORT_HIGH,
            56,
            TcpFlag::PshAck,
            seq,
            1001,
            65535,
            &data,
        );
        let data_pkt = parse(&data_frame).expect("parse data chunk");
        table.update(&data_pkt, ts);
        seq += 1400;
        ts += 0.05;
    }

    // 2s pause after last chunk (< cliff_timeout=3.0)
    let now = ts + 2.0;

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT_HIGH,
    };
    let flow = table.get(&key).expect("flow must exist");
    let result = throughput::detect_cliff(flow, &key, &config, now);

    assert!(result.is_none(), "2s pause after bursty traffic (< cliff_timeout=3s) must not trigger ThrottleCliff, got {:?}", result);
}
