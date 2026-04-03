#[path = "helpers/mod.rs"]
mod helpers;

use std::net::Ipv4Addr;

use flowsense::config::Config;
use flowsense::detect::throughput;
use flowsense::flow::{FlowKey, FlowTable};
use flowsense::parser::parse;
use flowsense::signal::Signal;
use helpers::{build_tcp_packet, TcpFlag};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const CLIENT_PORT: u16 = 54321;
// dst_port >= 1024 → classify_direction returns FromServer for non-SYN packets
const SERVER_PORT: u16 = 8443;

/// Feed SYN → SYN-ACK → PshAck data chunks of 1400 bytes from server
/// until at least `bytes_rx` total bytes have been received.
/// Returns the last timestamp used.
fn setup_transferring(table: &mut FlowTable, bytes_rx: u64) -> f64 {
    let mut ts = 1.0_f64;

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
    table.update(&syn_pkt, ts);
    ts += 0.1;

    // SYN-ACK from server → Established
    let syn_ack_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
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

    // Send data chunks of 1400 bytes from server → Transferring
    let chunk_size: usize = 1400;
    let mut total_sent: u64 = 0;
    let mut seq: u32 = 3000;
    while total_sent < bytes_rx {
        let data = vec![0xabu8; chunk_size];
        let data_frame = build_tcp_packet(
            SERVER,
            SERVER,
            CLIENT_PORT,
            SERVER_PORT,
            56,
            TcpFlag::PshAck,
            seq,
            1001,
            65535,
            &data,
        );
        let data_pkt = parse(&data_frame).expect("parse data");
        table.update(&data_pkt, ts);
        total_sent += chunk_size as u64;
        seq += chunk_size as u32;
        ts += 0.1;
    }

    ts
}

#[test]
fn test_throttle_cliff_at_16kb() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    let last_ts = setup_transferring(&mut table, 16384);

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");

    // 4s silence after last data → cliff
    let now = last_ts + 4.0;
    let signal = throughput::detect_cliff(flow, &key, &config, now);

    assert!(
        matches!(signal, Some(Signal::ThrottleCliff { .. })),
        "expected ThrottleCliff, got {:?}",
        signal
    );
}

#[test]
fn test_no_cliff_if_data_still_flowing() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    let last_ts = setup_transferring(&mut table, 16384);

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");

    // Only 1s silence — below cliff_timeout (3.0)
    let now = last_ts + 1.0;
    let signal = throughput::detect_cliff(flow, &key, &config, now);

    assert!(
        signal.is_none(),
        "expected None (still flowing), got {:?}",
        signal
    );
}

#[test]
fn test_no_cliff_if_large_transfer() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    // 1MB transferred — bytes_rx > cliff_threshold * 2 (40960)
    let last_ts = setup_transferring(&mut table, 1_048_576);

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");

    // 4s silence but bytes_rx >> threshold*2 → not a cliff
    let now = last_ts + 4.0;
    let signal = throughput::detect_cliff(flow, &key, &config, now);

    assert!(
        signal.is_none(),
        "expected None (large transfer), got {:?}",
        signal
    );
}

#[test]
fn test_probabilistic_throttle() {
    let config = Config::default();
    let mut table = FlowTable::new(config.flows.clone());

    let mut ts = 1.0_f64;

    // SYN
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
    table.update(&syn_pkt, ts);
    ts += 0.1;

    // SYN-ACK → Established
    let syn_ack_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
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

    // First server data packet → Transferring, seq=3000
    let data = vec![0xabu8; 1400];
    let data_frame = build_tcp_packet(
        SERVER,
        SERVER,
        CLIENT_PORT,
        SERVER_PORT,
        56,
        TcpFlag::PshAck,
        3000,
        1001,
        65535,
        &data,
    );
    let data_pkt = parse(&data_frame).expect("parse first data");
    table.update(&data_pkt, ts);
    ts += 1.0; // advance time for window

    // Repeat the same seq 10 times → 10 retransmits
    for _ in 0..10 {
        let retrans_frame = build_tcp_packet(
            SERVER,
            SERVER,
            CLIENT_PORT,
            SERVER_PORT,
            56,
            TcpFlag::PshAck,
            3000,
            1001,
            65535,
            &data,
        );
        let retrans_pkt = parse(&retrans_frame).expect("parse retrans");
        table.update(&retrans_pkt, ts);
        ts += 1.0;
    }

    let key = FlowKey {
        dst_ip: SERVER,
        dst_port: SERVER_PORT,
    };
    let flow = table.get(&key).expect("flow must exist");

    let signal = throughput::detect_retransmit(flow, &key, &config, ts);

    assert!(
        matches!(signal, Some(Signal::ThrottleProbabilistic { .. })),
        "expected ThrottleProbabilistic, got {:?}",
        signal
    );
}
