use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub domain: String,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

/// Parse a DNS response from raw UDP payload (everything after IP+UDP headers).
///
/// Returns `None` for queries (QR=0), truncated packets, zero A-record answers,
/// or packets that cannot be parsed.
pub fn parse_dns_response(data: &[u8]) -> Option<DnsResponse> {
    // DNS header is 12 bytes minimum
    if data.len() < 12 {
        return None;
    }

    let flags = ((data[2] as u16) << 8) | (data[3] as u16);

    // QR bit must be 1 (response)
    if flags & 0x8000 == 0 {
        return None;
    }

    let qdcount = ((data[4] as u16) << 8) | (data[5] as u16);
    let ancount = ((data[6] as u16) << 8) | (data[7] as u16);

    if ancount == 0 {
        return None;
    }

    // Parse question section to extract the domain name
    let mut pos = 12;
    let mut domain = String::new();

    for i in 0..qdcount {
        let (name, new_pos) = read_dns_name(data, pos)?;
        if i == 0 {
            domain = name;
        }
        pos = new_pos;
        // Skip QTYPE (2) + QCLASS (2)
        if pos + 4 > data.len() {
            return None;
        }
        pos += 4;
    }

    // Parse answer section: collect TYPE=A records
    let mut answers = Vec::new();

    for _ in 0..ancount {
        // Read name (usually a pointer like 0xC0 0x0C)
        let (_name, new_pos) = read_dns_name(data, pos)?;
        pos = new_pos;

        // TYPE (2) + CLASS (2) + TTL (4) + RDLENGTH (2) = 10 bytes
        if pos + 10 > data.len() {
            return None;
        }

        let rtype = ((data[pos] as u16) << 8) | (data[pos + 1] as u16);
        let _rclass = ((data[pos + 2] as u16) << 8) | (data[pos + 3] as u16);
        let ttl = ((data[pos + 4] as u32) << 24)
            | ((data[pos + 5] as u32) << 16)
            | ((data[pos + 6] as u32) << 8)
            | (data[pos + 7] as u32);
        let rdlength = ((data[pos + 8] as u16) << 8) | (data[pos + 9] as u16);
        pos += 10;

        if pos + rdlength as usize > data.len() {
            return None;
        }

        // TYPE=A (1), RDLENGTH=4
        if rtype == 1 && rdlength == 4 {
            let ip = Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
            answers.push(DnsAnswer { ip, ttl });
        }

        pos += rdlength as usize;
    }

    if answers.is_empty() {
        return None;
    }

    Some(DnsResponse { domain, answers })
}

/// Read a DNS domain name starting at `pos`, handling label compression (0xC0 pointers).
///
/// Returns the decoded name and the new position after the name field in the packet.
fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut return_pos = 0usize;

    // Safety: limit pointer chasing to prevent infinite loops
    let mut hops = 0u8;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len_byte = data[pos];

        if len_byte == 0 {
            // End of name
            if !jumped {
                return_pos = pos + 1;
            }
            break;
        }

        // Compression pointer: top two bits = 11
        if len_byte & 0xC0 == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                return_pos = pos + 2;
            }
            let offset = (((len_byte & 0x3F) as usize) << 8) | (data[pos + 1] as usize);
            pos = offset;
            jumped = true;
            hops += 1;
            if hops > 64 {
                return None;
            }
            continue;
        }

        // Regular label
        let label_len = len_byte as usize;
        pos += 1;
        if pos + label_len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[pos..pos + label_len]).ok()?;
        labels.push(label.to_string());
        pos += label_len;
    }

    if !jumped {
        // return_pos already set to pos + 1 in the len_byte == 0 branch
    }

    Some((labels.join("."), return_pos))
}
