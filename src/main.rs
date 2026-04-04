mod capture;
mod time;

use clap::Parser;
use std::io::{BufWriter, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use flowsense::{
    config::Config,
    detect, emit,
    flow::{self, FlowTable},
    parser, protocol,
    signal::Signal,
};

#[derive(Debug, Parser)]
#[command(
    name = "flowsense",
    about = "Passive DPI interference detector for Linux L2 bridges"
)]
struct Cli {
    /// Network interface to listen on
    #[arg(short = 'i', long, value_name = "INTERFACE")]
    interface: Option<String>,

    /// Read from pcap file instead of live capture
    #[arg(short = 'r', long, value_name = "FILE")]
    read: Option<PathBuf>,

    /// Write evidence to file (JSON lines)
    #[arg(short = 'w', long, value_name = "FILE")]
    write: Option<PathBuf>,

    /// Stop after <count> evidence events
    #[arg(short = 'c', long, value_name = "COUNT")]
    count: Option<u64>,

    /// Stop after <seconds>
    #[arg(long, value_name = "SECONDS")]
    duration: Option<f64>,

    /// Only track flows to this destination IP
    #[arg(long, value_name = "IP")]
    dst: Option<String>,

    /// Only track flows to this destination port
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,

    /// JSON lines output
    #[arg(long)]
    json: bool,

    /// Verbose — include flow metadata (SNI, bytes, timing)
    #[arg(short = 'v')]
    verbose: bool,

    /// Quiet — only confirmed signals, no warnings
    #[arg(short = 'q')]
    quiet: bool,

    /// Load thresholds from JSON config file
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Print default config and exit
    #[arg(long)]
    print_config: bool,

    /// Dump all flows to stderr on exit (diagnostic)
    #[arg(long)]
    dump_flows: bool,
}

fn collect_timeout_signals(
    table: &FlowTable,
    config: &Config,
    now: f64,
) -> Vec<(flow::FlowKey, Signal)> {
    table
        .iter()
        .flat_map(|(key, flow)| {
            [
                detect::drop::detect_timeout(flow, key, config, now),
                detect::throughput::detect_cliff(flow, key, config, now),
                detect::throughput::detect_retransmit(flow, key, config, now),
                detect::throughput::detect_ack_drop(flow, key, config, now),
            ]
            .into_iter()
            .flatten()
            .map(move |sig| (*key, sig))
        })
        .collect()
}

fn packet_matches_filter(
    dst_ip: Ipv4Addr,
    dst_port: u16,
    filter_dst: Option<Ipv4Addr>,
    filter_port: Option<u16>,
) -> bool {
    let ip_ok = filter_dst.is_none_or(|f| f == dst_ip);
    let port_ok = filter_port.is_none_or(|p| p == dst_port);
    ip_ok && port_ok
}

fn signal_matches_filter(
    signal: &Signal,
    filter_dst: Option<Ipv4Addr>,
    filter_port: Option<u16>,
) -> bool {
    let dst_ip: Ipv4Addr = signal.dst_ip().parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
    packet_matches_filter(dst_ip, signal.dst_port(), filter_dst, filter_port)
}

fn emit_signal<W: Write>(signal: &Signal, json: bool, out: &mut W) {
    let line = if json {
        emit::format_json(signal)
    } else {
        emit::format_human(signal)
    };
    let _ = writeln!(out, "{}", line);
    let _ = out.flush();
}

// Process-global running flag written by the OS signal handler.
static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn sigint_handler(_sig: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

fn main() {
    let cli = Cli::parse();

    if cli.print_config {
        let cfg = Config::default();
        println!("{}", cfg.to_json_pretty());
        return;
    }

    if cli.interface.is_none() && cli.read.is_none() {
        protocol::emit(&protocol::state_fatal(
            "either -i <interface> or -r <file> is required",
        ));
        std::process::exit(1);
    }

    let cfg = match cli.config {
        Some(ref path) => match Config::from_file(path) {
            Ok(c) => c,
            Err(e) => {
                protocol::emit(&protocol::state_fatal(&format!(
                    "failed to load config from {}: {}",
                    path.display(),
                    e
                )));
                std::process::exit(1);
            }
        },
        None => Config::default(),
    };

    // Parse filter options
    let filter_dst: Option<Ipv4Addr> = cli.dst.as_deref().and_then(|s| {
        s.parse()
            .map_err(|_| eprintln!("warning: invalid --dst IP '{}', ignoring filter", s))
            .ok()
    });
    let filter_port: Option<u16> = cli.port;

    // Setup output writer
    let mut out: Box<dyn Write> = match cli.write {
        Some(ref path) => match std::fs::File::create(path) {
            Ok(f) => Box::new(BufWriter::new(f)),
            Err(e) => {
                eprintln!("error: cannot open output file {}: {}", path.display(), e);
                std::process::exit(1);
            }
        },
        None => Box::new(BufWriter::new(std::io::stdout())),
    };

    // Register SIGINT / SIGTERM handlers
    unsafe {
        libc::signal(
            libc::SIGINT,
            sigint_handler as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            sigint_handler as *const () as libc::sighandler_t,
        );
    }

    // Open capture
    let interface = match cli.interface {
        Some(ref iface) => iface.as_str(),
        None => {
            eprintln!("error: -r pcap file mode is not yet implemented, use -i <interface>");
            std::process::exit(1);
        }
    };

    let mut cap = match capture::Capture::open(
        interface,
        cfg.capture.snaplen as usize,
        cfg.capture.promisc,
    ) {
        Ok(c) => c,
        Err(e) => {
            protocol::emit(&protocol::state_fatal(&format!(
                "failed to open capture on {}: {}",
                interface, e
            )));
            std::process::exit(1);
        }
    };

    let clock = time::Clock::new();
    let mut table = FlowTable::new(cfg.flows.clone());

    let mut packets_seen: u64 = 0;
    let mut signal_count: u64 = 0;
    let mut last_periodic_check = clock.now_secs();
    let periodic_interval = 5.0_f64;

    protocol::emit(&protocol::state_alive(env!("CARGO_PKG_VERSION")));

    if !cli.quiet {
        eprintln!(
            "flowsense: listening on {} (filter: dst={} port={})",
            interface,
            filter_dst
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| "any".to_string()),
            filter_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "any".to_string()),
        );
    }

    'main: loop {
        if !RUNNING.load(Ordering::Relaxed) {
            break;
        }

        let now = clock.now_secs();

        // Check duration limit
        if let Some(max_secs) = cli.duration {
            if now >= max_secs {
                break;
            }
        }

        // Receive next packet (poll returns None on 1s timeout)
        let raw = match cap.next_packet() {
            Some(bytes) => bytes,
            None => {
                // No packet — run periodic checks then continue
                let now_fresh = clock.now_secs();
                let elapsed = now_fresh - last_periodic_check;
                if elapsed >= periodic_interval {
                    let signals = collect_timeout_signals(&table, &cfg, now_fresh);
                    for (_fkey, sig) in &signals {
                        if signal_matches_filter(sig, filter_dst, filter_port) {
                            emit_signal(sig, cli.json, &mut out);
                            signal_count += 1;
                            if let Some(max) = cli.count {
                                if signal_count >= max {
                                    break 'main;
                                }
                            }
                        }
                    }
                    for (_fkey, _) in &signals {
                        table.mark_signal_fired(_fkey);
                    }
                    table.expire(now_fresh);
                    last_periodic_check = now_fresh;
                }
                continue;
            }
        };

        // Parse packet
        let pkt = match parser::parse(raw) {
            Some(p) => p,
            None => continue,
        };

        // Apply filter
        if !packet_matches_filter(pkt.dst_ip, pkt.dst_port, filter_dst, filter_port) {
            continue;
        }

        packets_seen += 1;

        // Update flow table
        table.update(&pkt, now);

        // Packet-based detection: injection signals
        let flow_key = flow::flow_key_from_packet(&pkt);
        if let Some(flow_state) = table.get(&flow_key) {
            if let Some(sig) = detect::injection::detect(&pkt, flow_state, &cfg, now) {
                emit_signal(&sig, cli.json, &mut out);
                signal_count += 1;
                if let Some(max) = cli.count {
                    if signal_count >= max {
                        break 'main;
                    }
                }
            }
        }

        // Periodic time-based detectors (every 5 seconds)
        let elapsed = now - last_periodic_check;
        if elapsed >= periodic_interval {
            let signals = collect_timeout_signals(&table, &cfg, now);
            for (_fkey, sig) in &signals {
                if signal_matches_filter(sig, filter_dst, filter_port) {
                    emit_signal(sig, cli.json, &mut out);
                    signal_count += 1;
                    if let Some(max) = cli.count {
                        if signal_count >= max {
                            break 'main;
                        }
                    }
                }
            }
            for (_fkey, _) in &signals {
                table.mark_signal_fired(_fkey);
            }
            table.expire(now);
            protocol::emit(&protocol::data_gauge(
                packets_seen,
                table.len() as u64,
                signal_count,
                now,
            ));
            last_periodic_check = now;
        }
    }

    // Dump all flows for diagnostic purposes
    if cli.dump_flows {
        eprintln!("flowsense: === flow dump ===");
        let mut flows: Vec<_> = table.iter().collect();
        flows.sort_by(|a, b| a.1.syn_ts.partial_cmp(&b.1.syn_ts).unwrap());
        for (key, flow) in flows {
            eprintln!(
                "  {:>15}:{:<5}  phase={:<13}  ttl_base={:<4}  hello={:<5}  sni={:<30}  rx={:<8}  tx={:<8}  retx_c={} retx_s={} rst_salvo={}",
                key.dst_ip,
                key.dst_port,
                format!("{:?}", flow.phase),
                flow.ttl_baseline.map(|t| t.to_string()).unwrap_or("-".into()),
                flow.has_client_hello,
                flow.sni.as_deref().unwrap_or("-"),
                flow.bytes_rx,
                flow.bytes_tx,
                flow.retransmit_count,
                flow.server_retransmit_count,
                flow.rst_salvo_count,
            );
        }
        eprintln!("flowsense: === end flow dump ===");
    }

    // Print summary on exit
    let final_now = clock.now_secs();
    eprintln!(
        "flowsense: done — packets={} signals={} flows={} elapsed={:.1}s",
        packets_seen,
        signal_count,
        table.len(),
        final_now,
    );
}
