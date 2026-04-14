use std::net::Ipv4Addr;

use flowsense::dns::parse_dns_response;

/// Build a DNS response packet (UDP payload only, no IP/UDP headers).
///
/// Constructs: header + question section + answer section with TYPE=A records.
fn build_dns_response(domain: &str, ips: &[(Ipv4Addr, u32)], qr: bool, ancount: u16) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Transaction ID
    pkt.push(0xAB);
    pkt.push(0xCD);

    // Flags: QR=qr, RD=1, RA=1
    let flags: u16 = if qr {
        0x8180 // QR=1, RD=1, RA=1
    } else {
        0x0100 // QR=0, RD=1
    };
    pkt.push((flags >> 8) as u8);
    pkt.push((flags & 0xFF) as u8);

    // QDCOUNT = 1
    pkt.push(0x00);
    pkt.push(0x01);

    // ANCOUNT
    pkt.push((ancount >> 8) as u8);
    pkt.push((ancount & 0xFF) as u8);

    // NSCOUNT = 0
    pkt.push(0x00);
    pkt.push(0x00);

    // ARCOUNT = 0
    pkt.push(0x00);
    pkt.push(0x00);

    // Question section: encode domain as DNS labels
    let question_name_offset = pkt.len(); // offset 12 = 0x0C
    let _ = question_name_offset;
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0x00); // root label

    // QTYPE = A (1)
    pkt.push(0x00);
    pkt.push(0x01);

    // QCLASS = IN (1)
    pkt.push(0x00);
    pkt.push(0x01);

    // Answer section
    for (ip, ttl) in ips.iter().take(ancount as usize) {
        // Name pointer to offset 0x0C (question section domain)
        pkt.push(0xC0);
        pkt.push(0x0C);

        // TYPE = A (1)
        pkt.push(0x00);
        pkt.push(0x01);

        // CLASS = IN (1)
        pkt.push(0x00);
        pkt.push(0x01);

        // TTL
        pkt.push((ttl >> 24) as u8);
        pkt.push((ttl >> 16) as u8);
        pkt.push((ttl >> 8) as u8);
        pkt.push((ttl & 0xFF) as u8);

        // RDLENGTH = 4
        pkt.push(0x00);
        pkt.push(0x04);

        // RDATA = IP address
        let octets = ip.octets();
        pkt.extend_from_slice(&octets);
    }

    pkt
}

#[test]
fn parse_single_a_record() {
    let ip = Ipv4Addr::new(142, 250, 74, 110);
    let ttl = 300u32;
    let pkt = build_dns_response("youtube.com", &[(ip, ttl)], true, 1);

    let resp = parse_dns_response(&pkt).expect("must parse single A record");
    assert_eq!(resp.domain, "youtube.com");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(resp.answers[0].ip, ip);
    assert_eq!(resp.answers[0].ttl, ttl);
}

#[test]
fn parse_multiple_a_records() {
    let ip1 = Ipv4Addr::new(142, 250, 74, 110);
    let ip2 = Ipv4Addr::new(142, 250, 74, 111);
    let pkt = build_dns_response("youtube.com", &[(ip1, 300), (ip2, 120)], true, 2);

    let resp = parse_dns_response(&pkt).expect("must parse multiple A records");
    assert_eq!(resp.domain, "youtube.com");
    assert_eq!(resp.answers.len(), 2);
    assert_eq!(resp.answers[0].ip, ip1);
    assert_eq!(resp.answers[0].ttl, 300);
    assert_eq!(resp.answers[1].ip, ip2);
    assert_eq!(resp.answers[1].ttl, 120);
}

#[test]
fn parse_query_returns_none() {
    let ip = Ipv4Addr::new(142, 250, 74, 110);
    let pkt = build_dns_response("youtube.com", &[(ip, 300)], false, 1);

    assert!(
        parse_dns_response(&pkt).is_none(),
        "query (QR=0) must return None"
    );
}

#[test]
fn parse_truncated_packet_returns_none() {
    let data = [0xAB, 0xCD];
    assert!(
        parse_dns_response(&data).is_none(),
        "truncated packet must return None"
    );
}

#[test]
fn parse_zero_answers_returns_none() {
    let pkt = build_dns_response("youtube.com", &[], true, 0);
    assert!(
        parse_dns_response(&pkt).is_none(),
        "zero answers must return None"
    );
}
