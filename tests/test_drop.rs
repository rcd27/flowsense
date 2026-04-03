#[path = "helpers/mod.rs"]
mod helpers;

use std::net::Ipv4Addr;

use flowsense::config::Config;
use flowsense::detect::drop::detect_timeout;
use flowsense::flow::{FlowKey, FlowTable};
use flowsense::parser::parse;
use flowsense::signal::Signal;
use helpers::{build_tcp_packet, tls_client_hello, TcpFlag};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const CLIENT_PORT: u16 = 54321;
// PORT < 1024 → classify_direction returns FromClient for non-SYN packets
const SERVER_PORT: u16 = 443;

fn send_syn(table: &mut FlowTable, ts: f64) {
    let frame = build_tcp_packet(
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
    let pkt = parse(&frame).expect("parse syn");
    table.update(&pkt, ts);
}

fn send_syn_ack(table: &mut FlowTable, ts: f64) {
    let frame = build_tcp_packet(
        SERVER,
        CLIENT,
        SERVER_PORT,
        CLIENT_PORT,
        52,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let pkt = parse(&frame).expect("parse syn_ack");
    table.update(&pkt, ts);
}

fn send_client_hello(table: &mut FlowTable, ts: f64) {
    let payload = tls_client_hello("example.com");
    let frame = build_tcp_packet(
        CLIENT,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        64,
        TcpFlag::PshAck,
        1001,
        2001,
        65535,
        &payload,
    );
    let pkt = parse(&frame).expect("parse client_hello");
    table.update(&pkt, ts);
}

#[test]
fn test_ip_blackhole_after_syn_timeout() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    send_syn(&mut table, 0.0);

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let signal = detect_timeout(flow, &key, &config, 6.0);

    assert!(
        matches!(signal, Some(Signal::IpBlackhole { dst_port: 443, .. })),
        "expected IpBlackhole at t=6, got {:?}",
        signal
    );
}

#[test]
fn test_no_blackhole_before_timeout() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    send_syn(&mut table, 0.0);

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");
    let signal = detect_timeout(flow, &key, &config, 3.0);

    assert!(
        signal.is_none(),
        "expected None at t=3 (before timeout), got {:?}",
        signal
    );
}

#[test]
fn test_silent_drop_after_client_hello() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    // SYN at t=0, SYN-ACK at t=0.5, ClientHello at t=1.0
    send_syn(&mut table, 0.0);
    send_syn_ack(&mut table, 0.5);
    send_client_hello(&mut table, 1.0);

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");

    // client_hello_ts=1.0, post_hello_timeout=10.0 → triggers at now >= 11.0
    let signal = detect_timeout(flow, &key, &config, 11.0);

    assert!(
        matches!(
            signal,
            Some(Signal::SilentDrop { dst_port: 443, sni: Some(ref s), .. }) if s == "example.com"
        ),
        "expected SilentDrop with sni=example.com at t=11, got {:?}",
        signal
    );
}

#[test]
fn test_no_silent_drop_if_server_responded() {
    // Use PORT_HIGH so that server data is classified as FromServer
    const PORT_HIGH: u16 = 8443;

    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    // SYN
    let syn_frame = build_tcp_packet(
        CLIENT,
        SERVER,
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
    table.update(&syn_pkt, 0.0);

    // SYN-ACK → Established (server responds to client)
    let syn_ack_frame = build_tcp_packet(
        SERVER,
        CLIENT,
        PORT_HIGH,
        CLIENT_PORT,
        52,
        TcpFlag::SynAck,
        2000,
        1001,
        65535,
        &[],
    );
    let syn_ack_pkt = parse(&syn_ack_frame).expect("parse syn_ack");
    table.update(&syn_ack_pkt, 0.5);

    // Server data: from SERVER to CLIENT → FromServer → bytes_rx > 0, phase=Transferring
    let data = vec![0xabu8; 100];
    let data_frame = build_tcp_packet(
        SERVER,
        CLIENT,
        PORT_HIGH,
        CLIENT_PORT,
        52,
        TcpFlag::PshAck,
        3000,
        1001,
        65535,
        &data,
    );
    let data_pkt = parse(&data_frame).expect("parse server_data");
    table.update(&data_pkt, 1.0);

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: PORT_HIGH,
    };
    let flow = table.get(&key).expect("flow must exist");

    // Phase is Transferring (server responded) → detect_timeout returns None
    let signal = detect_timeout(flow, &key, &config, 20.0);

    assert!(
        signal.is_none(),
        "expected None when server responded, got {:?}",
        signal
    );
}
