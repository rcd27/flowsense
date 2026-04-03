mod helpers;

use std::net::Ipv4Addr;

use flowsense::parser::{parse, Protocol, TcpFlagSet};
use helpers::{build_tcp_packet, build_udp_packet, tls_client_hello, TcpFlag};

#[test]
fn test_parse_tcp_syn() {
    let src_ip = Ipv4Addr::new(192, 168, 1, 10);
    let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
    let frame = build_tcp_packet(
        src_ip,
        dst_ip,
        54321,
        443,
        64,
        TcpFlag::Syn,
        0xdeadbeef,
        0,
        65535,
        &[],
    );
    let pkt = parse(&frame).expect("must parse");

    assert_eq!(pkt.src_ip, src_ip);
    assert_eq!(pkt.dst_ip, dst_ip);
    assert_eq!(pkt.src_port, 54321);
    assert_eq!(pkt.dst_port, 443);
    assert_eq!(pkt.ttl, 64);
    assert_eq!(pkt.protocol, Protocol::Tcp);
    assert_eq!(pkt.tcp_flags, TcpFlagSet::SYN);
    assert!(pkt.tcp_flags.has_syn());
    assert!(!pkt.tcp_flags.has_rst());
    assert!(!pkt.tcp_flags.has_fin());
    assert_eq!(pkt.tcp_seq, 0xdeadbeef);
    assert_eq!(pkt.tcp_ack, 0);
    assert_eq!(pkt.tcp_window, 65535);
    assert_eq!(pkt.payload_len, 0);
    assert!(!pkt.has_client_hello);
    assert!(pkt.sni.is_none());
}

#[test]
fn test_parse_tcp_rst_with_ttl() {
    let src_ip = Ipv4Addr::new(10, 0, 0, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 0, 5);
    let frame = build_tcp_packet(
        src_ip,
        dst_ip,
        80,
        12345,
        61,
        TcpFlag::RstAck,
        0x1000,
        0x2000,
        8192,
        &[],
    );
    let pkt = parse(&frame).expect("must parse");

    assert_eq!(pkt.ttl, 61);
    assert_eq!(pkt.protocol, Protocol::Tcp);
    assert_eq!(pkt.tcp_flags, TcpFlagSet::RST_ACK);
    assert!(pkt.tcp_flags.has_rst());
    assert!(!pkt.tcp_flags.has_fin());
    assert!(!pkt.tcp_flags.has_syn());
    assert_eq!(pkt.tcp_seq, 0x1000);
    assert_eq!(pkt.tcp_ack, 0x2000);
    assert_eq!(pkt.tcp_window, 8192);
}

#[test]
fn test_parse_sni_from_client_hello() {
    let sni = "example.com";
    let payload = tls_client_hello(sni);
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
    let frame = build_tcp_packet(
        src_ip,
        dst_ip,
        50000,
        443,
        64,
        TcpFlag::PshAck,
        1,
        1,
        65535,
        &payload,
    );
    let pkt = parse(&frame).expect("must parse");

    assert_eq!(pkt.protocol, Protocol::Tcp);
    assert!(pkt.has_client_hello);
    assert_eq!(pkt.sni.as_deref(), Some(sni));
    assert!(pkt.payload_len > 0);
}

#[test]
fn test_parse_too_short_returns_none() {
    let short = [0x00u8; 10];
    assert!(parse(&short).is_none());

    // Ethernet header only, no IP
    let eth_only = [0xffu8; 14];
    assert!(parse(&eth_only).is_none());
}

#[test]
fn test_parse_udp() {
    let src_ip = Ipv4Addr::new(192, 168, 1, 5);
    let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
    let dns_query = [
        0x00u8, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let frame = build_udp_packet(src_ip, dst_ip, 12345, 53, 64, &dns_query);
    let pkt = parse(&frame).expect("must parse UDP");

    assert_eq!(pkt.src_ip, src_ip);
    assert_eq!(pkt.dst_ip, dst_ip);
    assert_eq!(pkt.src_port, 12345);
    assert_eq!(pkt.dst_port, 53);
    assert_eq!(pkt.ttl, 64);
    assert_eq!(pkt.protocol, Protocol::Udp);
    assert_eq!(pkt.payload_len, dns_query.len());
    assert!(!pkt.has_client_hello);
    assert!(pkt.sni.is_none());
}
