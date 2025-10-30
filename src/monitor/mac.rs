use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Caches recently observed MAC addresses per IPv4 host.
pub struct MacManager {
    cache: HashMap<Ipv4Addr, (Instant, [u8; 6])>,
    ttl: Duration,
}

impl MacManager {
    /// Create a new MAC manager with a configurable TTL (e.g., 10 minutes)
    pub fn new(ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
        }
    }

    /// Store or refresh a MAC entry for an IP.
    /// Returns `true` if the MAC was newly inserted or changed, `false` otherwise.
    pub fn update(&mut self, ip: Ipv4Addr, mac: [u8; 6]) -> bool {
        match self.cache.get_mut(&ip) {
            // Existing entry — check for change
            Some((last_seen, old_mac)) => {
                *last_seen = Instant::now();
                if *old_mac != mac {
                    *old_mac = mac;
                    true // MAC changed
                } else {
                    false // No change
                }
            }
            // New entry
            None => {
                self.cache.insert(ip, (Instant::now(), mac));
                true
            }
        }
    }

    /// Retrieve a cached MAC if it’s still valid.
    pub fn get(&self, ip: &Ipv4Addr) -> Option<[u8; 6]> {
        self.cache
            .get(ip)
            .filter(|(t, _)| t.elapsed() <= self.ttl)
            .map(|(_, mac)| *mac)
    }

    /// Convert a MAC address to a colon-separated uppercase string.
    fn mac_to_string(mac: &[u8; 6]) -> String {
        mac.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    /// Retrieve formatted MAC string for an IP if valid.
    pub fn get_as_string(&self, ip: &Ipv4Addr) -> Option<String> {
        self.get(ip).map(|mac| Self::mac_to_string(&mac))
    }

    /// Clean up expired entries.
    pub fn prune_expired(&mut self) {
        let ttl = self.ttl;
        self.cache.retain(|_, (t, _)| t.elapsed() <= ttl);
    }
}
