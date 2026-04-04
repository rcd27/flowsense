//! DPI interference detectors.
//!
//! Three detector families, two execution models:
//!
//! **Packet-based (immediate):**
//!   - `injection` — fires on suspicious individual packets (RST/FIN/window)
//!
//! **Time-based (periodic, every 5 seconds):**
//!   - `drop` — fires on absence of expected responses (blackhole, silent drop)
//!   - `throughput` — fires on degraded transfer quality (cliff, retransmit, ACK drop)

pub mod drop;
pub mod injection;
pub mod throughput;
