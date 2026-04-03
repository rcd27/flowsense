#[path = "helpers/mod.rs"]
mod helpers;

use std::net::Ipv4Addr;

use flowsense::config::Config;
use flowsense::detect::injection;
use flowsense::flow::{FlowKey, FlowTable};
use flowsense::parser::parse;
use flowsense::signal::Signal;
use helpers::{build_tcp_packet, tls_client_hello, TcpFlag};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const CLIENT_PORT: u16 = 54321;
// dst_port < 1024 → classify_direction returns FromClient for non-SYN packets
const SERVER_PORT: u16 = 443;

fn setup_established_flow(table: &mut FlowTable, baseline_ttl: u8) -> f64 {
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

    2.0 // client_hello_ts
}

#[test]
fn test_rst_injection_by_ttl_anomaly() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());
    let hello_ts = setup_established_flow(&mut table, 52);

    // RST with anomalous TTL 61 (baseline 52, delta 9 > tolerance 2)
    let rst_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        61,
        TcpFlag::Rst,
        3000,
        0,
        0,
        &[],
    );
    let rst_pkt = parse(&rst_frame).expect("parse rst");
    let ts = hello_ts + 0.1; // within injection_window (500ms)

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let signal = injection::detect(&rst_pkt, flow, &config, ts);

    assert!(
        matches!(
            signal,
            Some(Signal::RstInjection {
                ttl_expected: 52,
                ttl_actual: 61,
                ..
            })
        ),
        "expected RstInjection with ttl_expected=52 ttl_actual=61, got {:?}",
        signal
    );
}

#[test]
fn test_rst_with_normal_ttl_no_signal() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());
    setup_established_flow(&mut table, 52);

    // RST with TTL 53 (baseline 52, delta 1 ≤ tolerance 2) → no anomaly
    let rst_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        53,
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
    let signal = injection::detect(&rst_pkt, flow, &config, 2.5);

    assert!(
        signal.is_none(),
        "expected None for normal TTL RST, got {:?}",
        signal
    );
}

#[test]
fn test_fin_injection() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());
    setup_established_flow(&mut table, 52);

    // FIN with anomalous TTL 61 (delta 9 > tolerance 2)
    let fin_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        61,
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
    let signal = injection::detect(&fin_pkt, flow, &config, 2.5);

    assert!(
        matches!(
            signal,
            Some(Signal::FinInjection {
                ttl_expected: 52,
                ttl_actual: 61,
                ..
            })
        ),
        "expected FinInjection, got {:?}",
        signal
    );
}

#[test]
fn test_window_manipulation() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());
    setup_established_flow(&mut table, 52);

    // ACK with window=0 and anomalous TTL 61
    let ack_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        61,
        TcpFlag::Ack,
        3000,
        1001,
        0,
        &[],
    );
    let ack_pkt = parse(&ack_frame).expect("parse ack");

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let signal = injection::detect(&ack_pkt, flow, &config, 2.5);

    assert!(
        matches!(
            signal,
            Some(Signal::WindowManipulation {
                ttl_expected: 52,
                ttl_actual: 61,
                window_value: 0,
                ..
            })
        ),
        "expected WindowManipulation, got {:?}",
        signal
    );
}
