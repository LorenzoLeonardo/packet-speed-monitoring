use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::helpers;

/// Serializable struct for persistence (we can’t store Instant directly)
#[derive(Serialize, Deserialize)]
struct MacEntry {
    ip: Ipv4Addr,
    mac: [u8; 6],
}

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
    pub fn update(&mut self, ip: Ipv4Addr, mac: [u8; 6], subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
        if helpers::ip_in_subnet(ip, subnet, mask) && !helpers::is_reserved_ip(ip, subnet, mask) {
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
        } else {
            false
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

    /// Try to load cache from file, or start empty if it fails.
    async fn load_from_file<P: AsRef<Path>>(path: P, ttl: Duration) -> std::io::Result<Self> {
        let data = fs::read_to_string(path.as_ref()).await?;
        let mut cache = HashMap::new();

        if !data.is_empty()
            && let Ok(entries) = serde_json::from_str::<Vec<MacEntry>>(&data)
        {
            for entry in entries {
                cache.insert(entry.ip, (Instant::now(), entry.mac));
            }
        }

        Ok(Self { cache, ttl })
    }

    /// Save current cache to a JSON file (only valid entries)
    pub async fn save_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let ttl = self.ttl;
        let entries: Vec<MacEntry> = self
            .cache
            .iter()
            .filter(|(_, (t, _))| t.elapsed() <= ttl)
            .map(|(ip, (_, mac))| MacEntry { ip: *ip, mac: *mac })
            .collect();

        // Serialize current in-memory state
        let new_json = serde_json::to_string_pretty(&entries)?;

        // Read existing file (if any)
        let existing_json = fs::read_to_string(path.as_ref()).await.unwrap_or_default();

        // Compare before writing
        if existing_json != new_json {
            let mut file = fs::File::create(path).await?;
            file.write_all(new_json.as_bytes()).await?;
            file.flush().await?;
            log::info!("MAC cache updated ({} entries).", entries.len());
        }

        Ok(())
    }

    /// Load cache from file if possible; otherwise create a new one.
    pub async fn load_or_new<P: AsRef<std::path::Path>>(path: P, ttl: Duration) -> Self {
        match Self::load_from_file(path, ttl).await {
            Ok(manager) => {
                log::info!("Loaded MAC cache from file.");
                manager
            }
            Err(e) => {
                log::warn!("Failed to load MAC cache: {e}. Starting fresh.");
                Self::new(ttl)
            }
        }
    }
}
