use std::{collections::HashMap, net::Ipv4Addr, path::Path, sync::Arc};

use async_dns_lookup::AsyncDnsResolver;
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
    dns: AsyncDnsResolver,
    cache: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
}

impl HostnameManager {
    pub fn new(dns: AsyncDnsResolver) -> Self {
        Self {
            dns,
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

    pub async fn update_from_dns(&self, ip: &Ipv4Addr) {
        let hostname = {
            let cache_guard = self.cache.lock().await;
            cache_guard
                .get(ip)
                .cloned()
                .unwrap_or_else(|| ip.to_string())
        };

        if hostname == ip.to_string() {
            let cache = self.cache.clone();
            let ip_copy = *ip;
            let dns_clone = self.dns.clone();
            tokio::spawn(async move {
                let _ = Self::get_or_resolve_hostname(dns_clone, ip_copy, cache).await;
            });
        }
    }

    async fn get_or_resolve_hostname(
        dns: AsyncDnsResolver,
        ip: Ipv4Addr,
        cache: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
    ) -> String {
        {
            let cache_guard = cache.lock().await;
            if let Some(name) = cache_guard.get(&ip) {
                return name.clone();
            }
        }

        let resolved = dns.reverse_lookup(ip).await;

        let hostname = match resolved {
            Ok(name) => {
                log::debug!("Resolved {ip} -> {name}");
                name
            }
            Err(_) => {
                log::warn!("No reverse DNS for {ip}");
                ip.to_string()
            }
        };

        let mut cache_guard = cache.lock().await;
        cache_guard.insert(ip, hostname.clone());
        hostname
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
            log::info!("DHCP >> Hostname: {hostname} Assigned IP: {ip}");

            let mut cache = self.cache.lock().await;
            cache
                .entry(ip)
                .and_modify(|existing| {
                    // Only update if existing hostname is an IP (numeric)
                    if existing.parse::<Ipv4Addr>().is_ok() {
                        *existing = hostname.clone();
                        log::info!("Updated cached hostname for {ip} -> {hostname}");
                    }
                })
                .or_insert_with(|| {
                    log::info!("Inserted new hostname for {ip} -> {hostname}");
                    hostname.clone()
                });
        }
    }

    /// Try to load hostname cache from file, or start empty if failed.
    pub async fn load_or_new<P: AsRef<Path>>(dns: AsyncDnsResolver, path: P) -> Self {
        match Self::load_from_file(dns.clone(), &path).await {
            Ok(manager) => manager,
            Err(e) => {
                log::warn!("Failed to load hostname cache: {e}. Starting fresh.");
                Self::new(dns)
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
            log::info!("Hostname cache updated ({} entries).", entries.len());
        }

        Ok(())
    }

    /// Load hostname cache from JSON file.
    async fn load_from_file<P: AsRef<Path>>(
        dns: AsyncDnsResolver,
        path: P,
    ) -> std::io::Result<Self> {
        let data = fs::read_to_string(path).await?;
        let entries: Vec<HostEntry> = serde_json::from_str(&data).unwrap_or_default();

        let cache: HashMap<Ipv4Addr, String> =
            entries.into_iter().map(|e| (e.ip, e.hostname)).collect();

        Ok(Self {
            dns,
            cache: Arc::new(Mutex::new(cache)),
        })
    }
}
