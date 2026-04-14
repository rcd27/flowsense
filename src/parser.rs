use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(non_camel_case_types)]
pub enum TcpFlagSet {
    SYN,
    SYN_ACK,
    ACK,
    RST,
    RST_ACK,
    FIN,
    FIN_ACK,
    PSH_ACK,
    Other(u8),
}

impl TcpFlagSet {
    pub fn from_byte(b: u8) -> Self {
        match b {
            0x02 => TcpFlagSet::SYN,
            0x12 => TcpFlagSet::SYN_ACK,
            0x10 => TcpFlagSet::ACK,
            0x04 => TcpFlagSet::RST,
            0x14 => TcpFlagSet::RST_ACK,
            0x01 => TcpFlagSet::FIN,
            0x11 => TcpFlagSet::FIN_ACK,
            0x18 => TcpFlagSet::PSH_ACK,
            other => TcpFlagSet::Other(other),
        }
    }

    pub fn has_rst(self) -> bool {
        match self {
            TcpFlagSet::RST => true,
            TcpFlagSet::RST_ACK => true,
            TcpFlagSet::Other(b) => b & 0x04 != 0,
            _ => false,
        }
    }

    pub fn has_fin(self) -> bool {
        match self {
            TcpFlagSet::FIN => true,
            TcpFlagSet::FIN_ACK => true,
            TcpFlagSet::Other(b) => b & 0x01 != 0,
            _ => false,
        }
    }

    pub fn has_syn(self) -> bool {
        match self {
            TcpFlagSet::SYN => true,
            TcpFlagSet::SYN_ACK => true,
            TcpFlagSet::Other(b) => b & 0x02 != 0,
            _ => false,
        }
    }

    pub fn is_syn_ack(self) -> bool {
        matches!(self, TcpFlagSet::SYN_ACK)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl: u8,
    pub protocol: Protocol,
    pub tcp_flags: TcpFlagSet,
    pub tcp_seq: u32,
    pub tcp_ack: u32,
    pub tcp_window: u16,
    pub payload_len: usize,
    pub has_client_hello: bool,
    pub sni: Option<String>,
}

impl ParsedPacket {
    pub fn is_dns_response(&self) -> bool {
        self.protocol == Protocol::Udp && self.src_port == 53
    }
}

fn extract_sni(payload: &[u8]) -> Option<String> {
    // TLS record: content_type=0x16, version (2 bytes), length (2 bytes)
    if payload.len() < 5 {
        return None;
    }
    if payload[0] != 0x16 {
        return None;
    }
    // payload[1..3] = TLS version, payload[3..5] = record length
    let record_len = ((payload[3] as usize) << 8) | (payload[4] as usize);
    if payload.len() < 5 + record_len {
        return None;
    }
    // Handshake header starts at offset 5
    // type (1) + length (3) = 4 bytes
    if payload.len() < 9 {
        return None;
    }
    if payload[5] != 0x01 {
        // not ClientHello
        return None;
    }
    // ClientHello body starts at offset 9
    // client_version (2) + random (32) + session_id_len (1) = 35 bytes minimum
    let body_start = 9usize;
    if payload.len() < body_start + 35 {
        return None;
    }
    let session_id_len = payload[body_start + 34] as usize;
    let after_session = body_start + 35 + session_id_len;
    // cipher_suites_len (2)
    if payload.len() < after_session + 2 {
        return None;
    }
    let cipher_suites_len =
        ((payload[after_session] as usize) << 8) | (payload[after_session + 1] as usize);
    let after_ciphers = after_session + 2 + cipher_suites_len;
    // compression_methods_len (1)
    if payload.len() < after_ciphers + 1 {
        return None;
    }
    let compression_len = payload[after_ciphers] as usize;
    let after_compression = after_ciphers + 1 + compression_len;
    // extensions_len (2)
    if payload.len() < after_compression + 2 {
        return None;
    }
    let extensions_len =
        ((payload[after_compression] as usize) << 8) | (payload[after_compression + 1] as usize);
    let extensions_start = after_compression + 2;
    if payload.len() < extensions_start + extensions_len {
        return None;
    }
    let extensions = &payload[extensions_start..extensions_start + extensions_len];
    parse_sni_from_extensions(extensions)
}

fn parse_sni_from_extensions(data: &[u8]) -> Option<String> {
    let mut pos = 0usize;
    while pos + 4 <= data.len() {
        let ext_type = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let ext_len = ((data[pos + 2] as usize) << 8) | (data[pos + 3] as usize);
        pos += 4;
        if pos + ext_len > data.len() {
            return None;
        }
        if ext_type == 0x0000 {
            // SNI extension
            // server_name_list_len (2)
            if ext_len < 2 {
                return None;
            }
            let ext_data = &data[pos..pos + ext_len];
            let list_len = ((ext_data[0] as usize) << 8) | (ext_data[1] as usize);
            if ext_data.len() < 2 + list_len {
                return None;
            }
            let mut list_pos = 2usize;
            while list_pos + 3 <= 2 + list_len {
                let name_type = ext_data[list_pos];
                let name_len =
                    ((ext_data[list_pos + 1] as usize) << 8) | (ext_data[list_pos + 2] as usize);
                list_pos += 3;
                if list_pos + name_len > ext_data.len() {
                    return None;
                }
                if name_type == 0x00 {
                    let name_bytes = &ext_data[list_pos..list_pos + name_len];
                    return String::from_utf8(name_bytes.to_vec()).ok();
                }
                list_pos += name_len;
            }
            return None;
        }
        pos += ext_len;
    }
    None
}

/// Parse a TCP segment from the IP payload.
///
/// `real_ip_payload_len` is the real (pre-snaplen) IP payload size from the
/// IP total_len header. The actual `ip_payload` slice may be truncated.
/// We use the truncated slice for header/TLS parsing but report the REAL
/// payload length for accurate byte counters (bytes_rx, bytes_tx).
fn parse_tcp(
    ip_payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    real_ip_payload_len: usize,
) -> Option<ParsedPacket> {
    // TCP header minimum 20 bytes — need at least this much captured
    if ip_payload.len() < 20 {
        return None;
    }
    let src_port = ((ip_payload[0] as u16) << 8) | (ip_payload[1] as u16);
    let dst_port = ((ip_payload[2] as u16) << 8) | (ip_payload[3] as u16);
    let seq = ((ip_payload[4] as u32) << 24)
        | ((ip_payload[5] as u32) << 16)
        | ((ip_payload[6] as u32) << 8)
        | (ip_payload[7] as u32);
    let ack = ((ip_payload[8] as u32) << 24)
        | ((ip_payload[9] as u32) << 16)
        | ((ip_payload[10] as u32) << 8)
        | (ip_payload[11] as u32);
    let data_offset = (ip_payload[12] >> 4) as usize;
    let tcp_header_len = data_offset * 4;
    if tcp_header_len < 20 || ip_payload.len() < tcp_header_len {
        return None;
    }
    let flags = TcpFlagSet::from_byte(ip_payload[13]);
    let window = ((ip_payload[14] as u16) << 8) | (ip_payload[15] as u16);

    // Captured TCP payload (may be truncated by snaplen).
    // Used for TLS ClientHello detection — we only need the first ~6 bytes.
    let captured_payload = &ip_payload[tcp_header_len..];

    // Real TCP payload length from IP total_len (accurate even when truncated).
    // Used for byte counters (bytes_rx/bytes_tx) so throughput detection works.
    let payload_len = real_ip_payload_len.saturating_sub(tcp_header_len);

    let has_client_hello =
        captured_payload.len() >= 6 && captured_payload[0] == 0x16 && captured_payload[5] == 0x01;
    let sni = if has_client_hello {
        extract_sni(captured_payload)
    } else {
        None
    };

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ttl,
        protocol: Protocol::Tcp,
        tcp_flags: flags,
        tcp_seq: seq,
        tcp_ack: ack,
        tcp_window: window,
        payload_len,
        has_client_hello,
        sni,
    })
}

/// Parse a UDP datagram from the IP payload.
///
/// Like parse_tcp, uses `real_ip_payload_len` for accurate payload size.
fn parse_udp(
    ip_payload: &[u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ttl: u8,
    real_ip_payload_len: usize,
) -> Option<ParsedPacket> {
    // UDP header: 8 bytes
    if ip_payload.len() < 8 {
        return None;
    }
    let src_port = ((ip_payload[0] as u16) << 8) | (ip_payload[1] as u16);
    let dst_port = ((ip_payload[2] as u16) << 8) | (ip_payload[3] as u16);
    // Real payload length from IP header (not truncated by snaplen)
    let payload_len = real_ip_payload_len.saturating_sub(8);

    Some(ParsedPacket {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        ttl,
        protocol: Protocol::Udp,
        tcp_flags: TcpFlagSet::Other(0),
        tcp_seq: 0,
        tcp_ack: 0,
        tcp_window: 0,
        payload_len,
        has_client_hello: false,
        sni: None,
    })
}

pub fn parse(raw: &[u8]) -> Option<ParsedPacket> {
    // Ethernet header: 14 bytes
    if raw.len() < 14 {
        return None;
    }
    let ether_type = ((raw[12] as u16) << 8) | (raw[13] as u16);
    if ether_type != 0x0800 {
        // Not IPv4
        return None;
    }
    let ip = &raw[14..];
    // IP header minimum 20 bytes
    if ip.len() < 20 {
        return None;
    }
    let version = ip[0] >> 4;
    if version != 4 {
        return None;
    }
    let ihl = (ip[0] & 0x0f) as usize;
    let ip_header_len = ihl * 4;
    if ip_header_len < 20 || ip.len() < ip_header_len {
        return None;
    }
    // IP total_len is the REAL packet size (before snaplen truncation).
    // Captured bytes (ip.len()) may be less than total_len when snaplen < packet size.
    // We use the captured portion for header parsing, but report the REAL payload
    // length so that byte counters (bytes_rx, bytes_tx) reflect actual traffic volume.
    let total_len = ((ip[2] as usize) << 8) | (ip[3] as usize);
    let captured_len = ip.len().min(total_len);
    if captured_len < ip_header_len {
        return None;
    }
    let ttl = ip[8];
    let protocol = ip[9];
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    // Use captured bytes for parsing (we can only read what's in the buffer),
    // but pass total_len so parse_tcp/parse_udp can compute real payload size.
    let ip_payload = &ip[ip_header_len..captured_len];

    // real_ip_payload_len = total IP payload (may be larger than captured ip_payload)
    let real_ip_payload_len = total_len.saturating_sub(ip_header_len);

    match protocol {
        6 => parse_tcp(ip_payload, src_ip, dst_ip, ttl, real_ip_payload_len),
        17 => parse_udp(ip_payload, src_ip, dst_ip, ttl, real_ip_payload_len),
        _ => None,
    }
}
