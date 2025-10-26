use std::{
    collections::HashMap,
    net::Ipv4Addr,
    str,
    sync::Arc,
    time::{Duration, Instant},
};

use async_dns_lookup::AsyncDnsResolver;
use async_pcap::Packet;
use etherparse::{IpNumber, Ipv4HeaderSlice, UdpHeaderSlice};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub mac: [u8; 6],
    pub hostname: Option<String>,
    pub ip: Option<Ipv4Addr>,
    pub last_seen: Instant,
}

pub struct HostnameManager {
    dns: AsyncDnsResolver,
    cache: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
    leases: Arc<Mutex<HashMap<[u8; 6], DhcpLease>>>,
}

impl HostnameManager {
    pub fn new(dns: AsyncDnsResolver) -> Self {
        Self {
            dns,
            cache: Arc::new(Mutex::new(HashMap::new())),
            leases: Arc::new(Mutex::new(HashMap::new())),
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
        if packet.data.len() <= 14 {
            return;
        }

        // Ethernet header: bytes 6..12 = source MAC
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&packet.data[6..12]);

        // IPv4 header
        let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..]) else {
            return;
        };

        if ip.protocol() != IpNumber::UDP {
            return;
        }

        let ip_header_len = ip.slice().len();
        let transport_data = &packet.data[14 + ip_header_len..];
        let Ok(udp) = UdpHeaderSlice::from_slice(transport_data) else {
            return;
        };

        let src_port = udp.source_port();
        let dst_port = udp.destination_port();
        if !(src_port == 68 || dst_port == 68 || src_port == 67 || dst_port == 67) {
            return;
        }

        let udp_payload = &transport_data[8..];
        let msg_type = extract_dhcp_message_type(udp_payload);
        let hostname_opt = extract_dhcp_hostname(udp_payload);
        let yiaddr_opt = extract_dhcp_yiaddr(udp_payload);

        // Update lease info
        if let Some(msg_type) = msg_type {
            let mut leases = self.leases.lock().await;
            let entry = leases.entry(mac).or_insert(DhcpLease {
                mac,
                hostname: None,
                ip: None,
                last_seen: Instant::now(),
            });

            entry.last_seen = Instant::now();

            if let Some(host) = hostname_opt.clone() {
                entry.hostname = Some(host.clone());
            }

            match msg_type {
                1 => log::debug!("DHCP DISCOVER from {:?}", entry),
                3 => log::debug!("DHCP REQUEST from {:?}", entry),
                2 | 5 => {
                    // OFFER or ACK → final IP known
                    if let Some(ip_assigned) = yiaddr_opt {
                        entry.ip = Some(ip_assigned);

                        if let Some(host) = entry.hostname.clone() {
                            log::info!(
                                "DHCP {}: {:?} assigned {:?} (hostname={})",
                                if msg_type == 2 { "OFFER" } else { "ACK" },
                                entry.mac,
                                ip_assigned,
                                host
                            );

                            let mut cache = self.cache.lock().await;
                            cache.insert(ip_assigned, host);
                        }
                    }
                }
                7 => {
                    log::info!("DHCP RELEASE from {:?}", entry.mac);
                }
                _ => {}
            }
        }

        // Optionally, cleanup stale leases every ~5 minutes
        Self::cleanup_stale_leases(&self.leases).await;
    }

    async fn cleanup_stale_leases(leases: &Arc<Mutex<HashMap<[u8; 6], DhcpLease>>>) {
        let mut leases = leases.lock().await;
        let now = Instant::now();
        leases.retain(|_, lease| now.duration_since(lease.last_seen) < Duration::from_secs(300));
    }
}

/* -----------------------------
   DHCP Parsing Helpers
------------------------------*/

fn extract_dhcp_hostname(payload: &[u8]) -> Option<String> {
    if payload.len() < 240 {
        return None;
    }
    let opts = &payload[240..];
    let mut i = 0;
    while i < opts.len() {
        let opt = opts[i];
        if opt == 0xff {
            break;
        }
        if opt == 0x00 {
            i += 1;
            continue;
        }
        if i + 1 >= opts.len() {
            break;
        }
        let len = opts[i + 1] as usize;
        if i + 2 + len > opts.len() {
            break;
        }
        if opt == 12 {
            if let Ok(s) = str::from_utf8(&opts[i + 2..i + 2 + len]) {
                return Some(s.to_string());
            } else {
                return Some(hex::encode(&opts[i + 2..i + 2 + len]));
            }
        }
        i += 2 + len;
    }
    None
}

fn extract_dhcp_yiaddr(payload: &[u8]) -> Option<Ipv4Addr> {
    if payload.len() >= 20 {
        Some(Ipv4Addr::new(
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ))
    } else {
        None
    }
}

fn extract_dhcp_message_type(payload: &[u8]) -> Option<u8> {
    if payload.len() < 240 {
        return None;
    }
    let mut i = 240;
    while i + 2 < payload.len() {
        let option_type = payload[i];
        if option_type == 255 {
            break;
        }
        let len = payload[i + 1] as usize;
        if i + 2 + len > payload.len() {
            break;
        }
        if option_type == 53 && len == 1 {
            return Some(payload[i + 2]);
        }
        i += 2 + len;
    }
    None
}
