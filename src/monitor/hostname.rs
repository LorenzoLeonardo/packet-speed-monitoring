use std::{collections::HashMap, net::Ipv4Addr, path::Path, sync::Arc};

use async_pcap::Packet;
use dhcproto::{
    Decodable,
    v4::{Decoder, DhcpOption, Message, OptionCode},
};
use etherparse::{Ipv4HeaderSlice, UdpHeaderSlice};
use serde::{Deserialize, Serialize};
use tokio::{fs, io::AsyncWriteExt, sync::Mutex};

#[derive(Serialize, Deserialize)]
struct HostEntry {
    ip: Ipv4Addr,
    hostname: String,
}

pub struct HostnameManager {
    cache: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
}

impl HostnameManager {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_hostname(&self, ip: &Ipv4Addr) -> String {
        let cache_guard = self.cache.lock().await;
        cache_guard
            .get(ip)
            .cloned()
            .unwrap_or_else(|| ip.to_string())
    }

    /// Parse and track DHCP messages.
    pub async fn update_from_dhcp(&self, packet: &Packet) {
        // Ensure packet has Ethernet + IP
        if packet.data.len() <= 14 {
            return;
        }

        // Extract source MAC (Ethernet bytes 6..12)
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&packet.data[6..12]);

        // IPv4 header
        let ip = match Ipv4HeaderSlice::from_slice(&packet.data[14..]) {
            Ok(ip) if ip.protocol() == etherparse::IpNumber::UDP => ip,
            _ => return,
        };

        // UDP header
        let ip_header_len = ip.slice().len();
        let udp_offset = 14 + ip_header_len;
        let transport_data = &packet.data[udp_offset..];

        let udp = match UdpHeaderSlice::from_slice(transport_data) {
            Ok(udp) => udp,
            Err(_) => return,
        };

        let (src_port, dst_port) = (udp.source_port(), udp.destination_port());
        if !(matches!(src_port, 67 | 68) || matches!(dst_port, 67 | 68)) {
            return;
        }

        // UDP payload → DHCP decode
        let udp_payload = &transport_data[8..];
        let msg = match Message::decode(&mut Decoder::new(udp_payload)) {
            Ok(msg) => msg,
            Err(e) => {
                log::error!("Failed to decode DHCP message: {:?}", e);
                return;
            }
        };

        // Extract hostname (Option 12)
        let hostname = msg
            .opts()
            .get(OptionCode::Hostname)
            .and_then(|opt| match opt {
                DhcpOption::Hostname(name) => Some(name.clone()),
                _ => None,
            });

        // Extract requested IP (Option 50)
        let ip_assigned = msg
            .opts()
            .get(OptionCode::RequestedIpAddress)
            .and_then(|opt| match opt {
                DhcpOption::RequestedIpAddress(ip) => Some(*ip),
                _ => None,
            })
            // fallback to yiaddr (the "your IP address" field)
            .or_else(|| {
                let yiaddr = msg.yiaddr();
                if yiaddr != Ipv4Addr::UNSPECIFIED {
                    Some(yiaddr)
                } else {
                    None
                }
            });

        if let (Some(hostname), Some(ip)) = (hostname, ip_assigned) {
            log::info!("[HostnameManager] DHCP >> Hostname: {hostname} Assigned IP: {ip}");

            let mut cache = self.cache.lock().await;

            // Remove old IP entry for this hostname if it exists
            if let Some((old_ip, _)) = cache
                .iter()
                .find(|(_, existing_name)| **existing_name == hostname)
                .map(|(k, v)| (*k, v.clone()))
                && old_ip != ip
            {
                cache.remove(&old_ip);
                log::info!("Removed old mapping {old_ip} -> {hostname}");
            }

            // Update or insert hostname for the new IP
            match cache.get(&ip) {
                Some(existing) if *existing != hostname => {
                    cache.insert(ip, hostname.clone());
                    log::info!("Updated hostname for {ip} -> {hostname}");
                }
                None => {
                    cache.insert(ip, hostname.clone());
                    log::info!("Inserted new hostname for {ip} -> {hostname}");
                }
                _ => {} // No change needed
            }
        }
    }

    /// Try to load hostname cache from file, or start empty if failed.
    pub async fn load_or_new<P: AsRef<Path>>(path: P) -> Self {
        match Self::load_from_file(&path).await {
            Ok(manager) => manager,
            Err(e) => {
                log::warn!("Failed to load hostname cache: {e}. Starting fresh.");
                Self::new()
            }
        }
    }

    /// Save hostname cache to JSON file — only if content changed.
    pub async fn save_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let cache_guard = self.cache.lock().await;

        let entries: Vec<HostEntry> = cache_guard
            .iter()
            .map(|(ip, name)| HostEntry {
                ip: *ip,
                hostname: name.clone(),
            })
            .collect();

        let new_json = serde_json::to_string_pretty(&entries)?;
        let existing_json = fs::read_to_string(path.as_ref()).await.unwrap_or_default();

        if existing_json != new_json {
            let mut file = fs::File::create(path).await?;
            file.write_all(new_json.as_bytes()).await?;
            file.flush().await?;
            log::debug!("Hostname cache updated ({} entries).", entries.len());
        }

        Ok(())
    }

    /// Load hostname cache from JSON file.
    async fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let data = fs::read_to_string(path).await?;
        let entries: Vec<HostEntry> = serde_json::from_str(&data).unwrap_or_default();

        let cache: HashMap<Ipv4Addr, String> =
            entries.into_iter().map(|e| (e.ip, e.hostname)).collect();

        Ok(Self {
            cache: Arc::new(Mutex::new(cache)),
        })
    }
}
