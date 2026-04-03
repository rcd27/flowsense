use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpFlag {
    Syn,    // 0x02
    SynAck, // 0x12
    Ack,    // 0x10
    Rst,    // 0x04
    RstAck, // 0x14
    Fin,    // 0x01
    FinAck, // 0x11
    PshAck, // 0x18
}

impl TcpFlag {
    pub fn bits(self) -> u8 {
        match self {
            TcpFlag::Syn => 0x02,
            TcpFlag::SynAck => 0x12,
            TcpFlag::Ack => 0x10,
            TcpFlag::Rst => 0x04,
            TcpFlag::RstAck => 0x14,
            TcpFlag::Fin => 0x01,
            TcpFlag::FinAck => 0x11,
            TcpFlag::PshAck => 0x18,
        }
    }
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        let word = ((header[i] as u32) << 8) | (header[i + 1] as u32);
        sum += word;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let tcp_len = tcp_segment.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + tcp_segment.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0x00);
    pseudo.push(0x06); // TCP protocol
    pseudo.push((tcp_len >> 8) as u8);
    pseudo.push((tcp_len & 0xff) as u8);
    pseudo.extend_from_slice(tcp_segment);
    ip_checksum(&pseudo)
}

fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let udp_len = udp_segment.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + udp_segment.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0x00);
    pseudo.push(0x11); // UDP protocol
    pseudo.push((udp_len >> 8) as u8);
    pseudo.push((udp_len & 0xff) as u8);
    pseudo.extend_from_slice(udp_segment);
    ip_checksum(&pseudo)
}

pub fn build_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    flags: TcpFlag,
    seq: u32,
    ack: u32,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    // Ethernet header: 14 bytes
    let eth_dst = [0xffu8; 6];
    let eth_src = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let eth_type = [0x08u8, 0x00]; // IPv4

    // TCP header: 20 bytes (no options, data offset = 5)
    let data_offset = 5u8; // 5 * 4 = 20 bytes
    let tcp_header_len = 20usize;
    let mut tcp_seg = vec![0u8; tcp_header_len + payload.len()];
    tcp_seg[0] = (src_port >> 8) as u8;
    tcp_seg[1] = (src_port & 0xff) as u8;
    tcp_seg[2] = (dst_port >> 8) as u8;
    tcp_seg[3] = (dst_port & 0xff) as u8;
    tcp_seg[4] = (seq >> 24) as u8;
    tcp_seg[5] = (seq >> 16) as u8;
    tcp_seg[6] = (seq >> 8) as u8;
    tcp_seg[7] = (seq & 0xff) as u8;
    tcp_seg[8] = (ack >> 24) as u8;
    tcp_seg[9] = (ack >> 16) as u8;
    tcp_seg[10] = (ack >> 8) as u8;
    tcp_seg[11] = (ack & 0xff) as u8;
    tcp_seg[12] = data_offset << 4; // data offset in high nibble
    tcp_seg[13] = flags.bits();
    tcp_seg[14] = (window >> 8) as u8;
    tcp_seg[15] = (window & 0xff) as u8;
    // checksum at [16..18] — computed below, urgent at [18..20] = 0
    tcp_seg[tcp_header_len..].copy_from_slice(payload);
    let csum = tcp_checksum(src_ip, dst_ip, &tcp_seg);
    tcp_seg[16] = (csum >> 8) as u8;
    tcp_seg[17] = (csum & 0xff) as u8;

    // IP header: 20 bytes
    let total_len = (20 + tcp_seg.len()) as u16;
    let mut ip_hdr = vec![0u8; 20];
    ip_hdr[0] = 0x45; // version=4, ihl=5
    ip_hdr[1] = 0x00; // DSCP/ECN
    ip_hdr[2] = (total_len >> 8) as u8;
    ip_hdr[3] = (total_len & 0xff) as u8;
    ip_hdr[4] = 0x00; // id high
    ip_hdr[5] = 0x01; // id low
    ip_hdr[6] = 0x00; // flags/frag offset
    ip_hdr[7] = 0x00;
    ip_hdr[8] = ttl;
    ip_hdr[9] = 0x06; // TCP
                      // checksum at [10..12] — computed below
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    ip_hdr[12..16].copy_from_slice(&src_octets);
    ip_hdr[16..20].copy_from_slice(&dst_octets);
    let ip_csum = ip_checksum(&ip_hdr);
    ip_hdr[10] = (ip_csum >> 8) as u8;
    ip_hdr[11] = (ip_csum & 0xff) as u8;

    let mut frame = Vec::with_capacity(14 + ip_hdr.len() + tcp_seg.len());
    frame.extend_from_slice(&eth_dst);
    frame.extend_from_slice(&eth_src);
    frame.extend_from_slice(&eth_type);
    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&tcp_seg);
    frame
}

pub fn build_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let eth_dst = [0xffu8; 6];
    let eth_src = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
    let eth_type = [0x08u8, 0x00];

    let udp_len = (8 + payload.len()) as u16;
    let mut udp_seg = vec![0u8; 8 + payload.len()];
    udp_seg[0] = (src_port >> 8) as u8;
    udp_seg[1] = (src_port & 0xff) as u8;
    udp_seg[2] = (dst_port >> 8) as u8;
    udp_seg[3] = (dst_port & 0xff) as u8;
    udp_seg[4] = (udp_len >> 8) as u8;
    udp_seg[5] = (udp_len & 0xff) as u8;
    // checksum at [6..8]
    udp_seg[8..].copy_from_slice(payload);
    let csum = udp_checksum(src_ip, dst_ip, &udp_seg);
    udp_seg[6] = (csum >> 8) as u8;
    udp_seg[7] = (csum & 0xff) as u8;

    let total_len = (20 + udp_seg.len()) as u16;
    let mut ip_hdr = vec![0u8; 20];
    ip_hdr[0] = 0x45;
    ip_hdr[1] = 0x00;
    ip_hdr[2] = (total_len >> 8) as u8;
    ip_hdr[3] = (total_len & 0xff) as u8;
    ip_hdr[4] = 0x00;
    ip_hdr[5] = 0x02;
    ip_hdr[6] = 0x00;
    ip_hdr[7] = 0x00;
    ip_hdr[8] = ttl;
    ip_hdr[9] = 0x11; // UDP
    let src_octets = src_ip.octets();
    let dst_octets = dst_ip.octets();
    ip_hdr[12..16].copy_from_slice(&src_octets);
    ip_hdr[16..20].copy_from_slice(&dst_octets);
    let ip_csum = ip_checksum(&ip_hdr);
    ip_hdr[10] = (ip_csum >> 8) as u8;
    ip_hdr[11] = (ip_csum & 0xff) as u8;

    let mut frame = Vec::with_capacity(14 + ip_hdr.len() + udp_seg.len());
    frame.extend_from_slice(&eth_dst);
    frame.extend_from_slice(&eth_src);
    frame.extend_from_slice(&eth_type);
    frame.extend_from_slice(&ip_hdr);
    frame.extend_from_slice(&udp_seg);
    frame
}

pub fn tls_client_hello(sni: &str) -> Vec<u8> {
    // Build a minimal TLS ClientHello with the given SNI
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len();

    // SNI extension content:
    //   server_name_list: [type=0x00, len(sni_len as 2 bytes), sni_bytes...]
    //   sni_list_len = 1 + 2 + sni_len
    let sni_name_len = sni_len as u16;
    let sni_list_entry_len = (1 + 2 + sni_len) as u16; // type + len + name
    let sni_ext_data_len = (2 + sni_list_entry_len) as u16; // list_len field + entries

    // Extension: type=0x0000, ext_len=sni_ext_data_len, data
    let ext_type: [u8; 2] = [0x00, 0x00];
    let ext_len_bytes = [
        (sni_ext_data_len >> 8) as u8,
        (sni_ext_data_len & 0xff) as u8,
    ];
    let sni_list_len_bytes = [
        (sni_list_entry_len >> 8) as u8,
        (sni_list_entry_len & 0xff) as u8,
    ];
    let sni_type_byte: u8 = 0x00;
    let sni_name_len_bytes = [(sni_name_len >> 8) as u8, (sni_name_len & 0xff) as u8];

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&ext_type);
    extensions.extend_from_slice(&ext_len_bytes);
    extensions.extend_from_slice(&sni_list_len_bytes);
    extensions.push(sni_type_byte);
    extensions.extend_from_slice(&sni_name_len_bytes);
    extensions.extend_from_slice(sni_bytes);

    let extensions_total_len = extensions.len() as u16;

    // ClientHello body (simplified):
    //   client_version: 0x0303 (TLS 1.2)
    //   random: 32 bytes
    //   session_id_len: 0
    //   cipher_suites_len: 2
    //   cipher_suites: [0x00, 0x2f]
    //   compression_methods_len: 1
    //   compression_methods: [0x00]
    //   extensions_len: extensions_total_len
    //   extensions: ...
    let mut hello_body = Vec::new();
    hello_body.extend_from_slice(&[0x03, 0x03]); // client_version
    hello_body.extend_from_slice(&[0u8; 32]); // random
    hello_body.push(0x00); // session_id_len
    hello_body.extend_from_slice(&[0x00, 0x02]); // cipher_suites_len
    hello_body.extend_from_slice(&[0x00, 0x2f]); // cipher suite TLS_RSA_WITH_AES_128_CBC_SHA
    hello_body.push(0x01); // compression_methods_len
    hello_body.push(0x00); // compression method: null
    hello_body.push((extensions_total_len >> 8) as u8);
    hello_body.push((extensions_total_len & 0xff) as u8);
    hello_body.extend_from_slice(&extensions);

    let hello_len = hello_body.len() as u32;

    // Handshake header: type=0x01 (ClientHello), length (3 bytes)
    let mut handshake = Vec::new();
    handshake.push(0x01); // HandshakeType::ClientHello
    handshake.push(((hello_len >> 16) & 0xff) as u8);
    handshake.push(((hello_len >> 8) & 0xff) as u8);
    handshake.push((hello_len & 0xff) as u8);
    handshake.extend_from_slice(&hello_body);

    let handshake_len = handshake.len() as u16;

    // TLS record header: content_type=0x16, version=0x0301, length
    let mut record = Vec::new();
    record.push(0x16); // content_type: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // version: TLS 1.0
    record.push((handshake_len >> 8) as u8);
    record.push((handshake_len & 0xff) as u8);
    record.extend_from_slice(&handshake);

    record
}
