//! In-memory DNS cache: maps IP addresses to domain names with TTL-based expiry.
//!
//! Used by FlowSense to resolve destination IPs back to domain names for
//! human-readable signal output. Populated from DNS response packets observed
//! on the bridge interface.
//!
//! # Eviction
//!
//! - Expired entries are removed by `cleanup()` (called periodically).
//! - When `max_entries` is exceeded on insert, the oldest entry (smallest
//!   `inserted_at`) is evicted to make room.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A cached DNS entry (private — callers only see domain via `lookup`).
struct Entry {
    domain: String,
    expires_at: f64,
    inserted_at: f64,
}

/// IP → domain cache with TTL expiry and bounded size.
pub struct DnsCache {
    entries: HashMap<Ipv4Addr, Entry>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Insert a DNS response: each IP in `ips` maps to `domain`.
    ///
    /// If the cache exceeds `max_entries` after insertion, the oldest entry
    /// (smallest `inserted_at`) is evicted.
    pub fn insert(&mut self, domain: &str, ips: &[Ipv4Addr], ttl_secs: f64, now: f64) {
        for &ip in ips {
            self.entries.insert(
                ip,
                Entry {
                    domain: domain.to_owned(),
                    expires_at: now + ttl_secs,
                    inserted_at: now,
                },
            );
        }

        while self.entries.len() > self.max_entries {
            self.evict_oldest();
        }
    }

    /// Look up the domain for `ip`, returning `None` if missing or expired.
    pub fn lookup(&self, ip: Ipv4Addr, now: f64) -> Option<&str> {
        self.entries.get(&ip).and_then(|entry| {
            if now <= entry.expires_at {
                Some(entry.domain.as_str())
            } else {
                None
            }
        })
    }

    /// Remove all expired entries.
    pub fn cleanup(&mut self, now: f64) {
        self.entries.retain(|_, entry| now <= entry.expires_at);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict the entry with the smallest `inserted_at`.
    fn evict_oldest(&mut self) {
        let oldest_ip = self
            .entries
            .iter()
            .min_by(|a, b| a.1.inserted_at.partial_cmp(&b.1.inserted_at).unwrap())
            .map(|(&ip, _)| ip);

        if let Some(ip) = oldest_ip {
            self.entries.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_lookup() {
        let mut cache = DnsCache::new(100);
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        cache.insert("example.com", &[ip], 60.0, 0.0);

        assert_eq!(cache.lookup(ip, 0.0), Some("example.com"));
    }

    #[test]
    fn lookup_multiple_ips_same_domain() {
        let mut cache = DnsCache::new(100);
        let ip1: Ipv4Addr = "142.250.74.206".parse().unwrap();
        let ip2: Ipv4Addr = "142.250.74.238".parse().unwrap();
        cache.insert("youtube.com", &[ip1, ip2], 300.0, 0.0);

        assert_eq!(cache.lookup(ip1, 0.0), Some("youtube.com"));
        assert_eq!(cache.lookup(ip2, 0.0), Some("youtube.com"));
    }

    #[test]
    fn lookup_expired_returns_none() {
        let mut cache = DnsCache::new(100);
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        cache.insert("example.com", &[ip], 60.0, 0.0);

        assert_eq!(cache.lookup(ip, 61.0), None);
    }

    #[test]
    fn lookup_not_found_returns_none() {
        let cache = DnsCache::new(100);
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();

        assert_eq!(cache.lookup(ip, 0.0), None);
    }

    #[test]
    fn cleanup_removes_expired() {
        let mut cache = DnsCache::new(100);
        let ip: Ipv4Addr = "1.2.3.4".parse().unwrap();
        cache.insert("example.com", &[ip], 60.0, 0.0);
        assert_eq!(cache.len(), 1);

        cache.cleanup(61.0);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn max_entries_evicts_oldest() {
        let mut cache = DnsCache::new(2);

        let ip1: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let ip2: Ipv4Addr = "2.2.2.2".parse().unwrap();
        let ip3: Ipv4Addr = "3.3.3.3".parse().unwrap();

        cache.insert("first.com", &[ip1], 300.0, 1.0);
        cache.insert("second.com", &[ip2], 300.0, 2.0);
        cache.insert("third.com", &[ip3], 300.0, 3.0);

        // first.com (oldest inserted_at=1.0) should be evicted
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup(ip1, 3.0), None);
        assert_eq!(cache.lookup(ip2, 3.0), Some("second.com"));
        assert_eq!(cache.lookup(ip3, 3.0), Some("third.com"));
    }

    #[test]
    fn insert_updates_existing_domain() {
        let mut cache = DnsCache::new(100);

        let old_ip: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let new_ip: Ipv4Addr = "2.2.2.2".parse().unwrap();

        cache.insert("example.com", &[old_ip], 60.0, 0.0);
        cache.insert("example.com", &[new_ip], 120.0, 10.0);

        // Old IP still resolves (it wasn't removed, just a new IP was added)
        assert_eq!(cache.lookup(old_ip, 10.0), Some("example.com"));
        // New IP also resolves
        assert_eq!(cache.lookup(new_ip, 10.0), Some("example.com"));
    }
}
