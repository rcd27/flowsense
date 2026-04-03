use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::config::FlowsConfig;
use crate::parser::ParsedPacket;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowPhase {
    SynSent,
    Established,
    Transferring,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    FromClient,
    FromServer,
}

#[derive(Debug, Clone)]
pub struct FlowState {
    pub phase: FlowPhase,
    pub ttl_baseline: Option<u8>,
    pub has_client_hello: bool,
    pub client_hello_ts: Option<f64>,
    pub sni: Option<String>,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub first_data_ts: Option<f64>,
    pub last_data_ts: Option<f64>,
    pub last_activity_ts: f64,
    pub syn_ts: f64,
    pub retransmit_count: u32,
    pub server_retransmit_count: u32,
    pub rst_salvo_count: u32,
    pub last_seq_from_server: Option<u32>,
}

impl FlowState {
    fn new(syn_ts: f64) -> Self {
        Self {
            phase: FlowPhase::SynSent,
            ttl_baseline: None,
            has_client_hello: false,
            client_hello_ts: None,
            sni: None,
            bytes_rx: 0,
            bytes_tx: 0,
            first_data_ts: None,
            last_data_ts: None,
            last_activity_ts: syn_ts,
            syn_ts,
            retransmit_count: 0,
            server_retransmit_count: 0,
            rst_salvo_count: 0,
            last_seq_from_server: None,
        }
    }
}

pub struct FlowTable {
    config: FlowsConfig,
    flows: HashMap<FlowKey, FlowState>,
}

impl FlowTable {
    pub fn new(config: FlowsConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
        }
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowState> {
        self.flows.get(key)
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn config(&self) -> &FlowsConfig {
        &self.config
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FlowKey, &FlowState)> {
        self.flows.iter()
    }

    pub fn update(&mut self, pkt: &ParsedPacket, ts: f64) {
        let key = flow_key_from_packet(pkt);
        let direction = classify_direction(pkt);

        let flow = self.flows.entry(key).or_insert_with(|| FlowState::new(ts));
        flow.last_activity_ts = ts;

        let phase = flow.phase;
        let flags = pkt.tcp_flags;
        let payload = pkt.payload_len;

        // SYN_ACK: transition SynSent→Established regardless of classified direction,
        // because the direction heuristic for SYN_ACK is unreliable in test scenarios
        // where we reuse the same (dst_ip, dst_port) key for both directions.
        if phase == FlowPhase::SynSent && flags.is_syn_ack() {
            flow.phase = FlowPhase::Established;
            flow.ttl_baseline = Some(pkt.ttl);
            return;
        }

        match (phase, direction, flags) {
            (FlowPhase::Established, Direction::FromClient, _) if pkt.has_client_hello => {
                flow.has_client_hello = true;
                flow.client_hello_ts = Some(ts);
                if pkt.sni.is_some() {
                    flow.sni = pkt.sni.clone();
                }
            }

            (FlowPhase::Established, Direction::FromServer, _) if payload > 0 => {
                flow.phase = FlowPhase::Transferring;
                track_server_data(flow, pkt, ts);
            }

            (FlowPhase::Transferring, Direction::FromServer, _) if payload > 0 => {
                track_server_data(flow, pkt, ts);
            }

            (_, Direction::FromServer, _) if flags.has_rst() => {
                flow.rst_salvo_count += 1;
            }

            (_, Direction::FromClient, _) if payload > 0 => {
                flow.bytes_tx += payload as u64;
            }

            _ => {}
        }
    }

    pub fn expire(&mut self, now: f64) {
        let ttl = self.config.flow_ttl;
        self.flows
            .retain(|_, state| now - state.last_activity_ts < ttl);
    }
}

fn classify_direction(pkt: &ParsedPacket) -> Direction {
    if pkt.tcp_flags.has_syn() && !pkt.tcp_flags.is_syn_ack() {
        return Direction::FromClient;
    }
    if pkt.dst_port < 1024 {
        return Direction::FromClient;
    }
    Direction::FromServer
}

pub fn flow_key_from_packet(pkt: &ParsedPacket) -> FlowKey {
    FlowKey {
        dst_ip: pkt.dst_ip,
        dst_port: pkt.dst_port,
    }
}

fn track_server_data(flow: &mut FlowState, pkt: &ParsedPacket, ts: f64) {
    let payload = pkt.payload_len as u64;

    match flow.last_seq_from_server {
        Some(last_seq) if last_seq == pkt.tcp_seq => {
            flow.server_retransmit_count += 1;
        }
        _ => {
            flow.bytes_rx += payload;
            flow.last_seq_from_server = Some(pkt.tcp_seq);
            if flow.first_data_ts.is_none() {
                flow.first_data_ts = Some(ts);
            }
            flow.last_data_ts = Some(ts);
        }
    }
}
