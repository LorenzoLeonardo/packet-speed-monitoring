use std::{collections::HashMap, net::Ipv4Addr, str, sync::Arc};

use async_dns_lookup::AsyncDnsResolver;
use async_pcap::Packet;
use etherparse::{IpNumber, Ipv4HeaderSlice, UdpHeaderSlice};
use tokio::sync::Mutex;

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

    pub async fn update_from_dhcp(&self, packet: &Packet) {
        if packet.data.len() <= 14 {
            return;
        }

        if let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..]) {
            let src_ip = ip.source_addr();

            // Skip if hostname already cached
            {
                let cache_guard = self.cache.lock().await;
                if cache_guard.contains_key(&src_ip) {
                    return;
                }
            }

            // Check UDP layer
            if ip.protocol() == IpNumber::UDP {
                let ip_header_len = ip.slice().len();
                let transport_data = &packet.data[14 + ip_header_len..];
                if let Ok(udp) = UdpHeaderSlice::from_slice(transport_data) {
                    let src_port = udp.source_port();
                    let dst_port = udp.destination_port();

                    if (src_port == 68 || dst_port == 68 || src_port == 67 || dst_port == 67)
                        && transport_data.len() >= 8
                    {
                        let udp_payload = &transport_data[8..];
                        let msg_type = extract_dhcp_message_type(udp_payload);

                        if let Some(msg_type) = msg_type {
                            match msg_type {
                                3 => {
                                    // DHCP REQUEST
                                    if let Some(host) = extract_dhcp_hostname(udp_payload) {
                                        log::info!(
                                            "DHCP REQUEST from {src_ip} (hostname: Some({host}))"
                                        );
                                        let mut cache_guard = self.cache.lock().await;
                                        cache_guard.insert(src_ip, host);
                                    }
                                }
                                2 | 5 => {
                                    // DHCP OFFER / ACK
                                    if let (Some(host), Some(ip_offered)) = (
                                        extract_dhcp_hostname(udp_payload),
                                        extract_dhcp_yiaddr(udp_payload),
                                    ) {
                                        log::info!(
                                            "DHCP {} from {src_ip} => {host} (offered IP: {ip_offered})",
                                            if msg_type == 2 { "OFFER" } else { "ACK" }
                                        );
                                        let mut cache_guard = self.cache.lock().await;
                                        cache_guard.insert(ip_offered, host);
                                    }
                                }
                                _ => (),
                            }
                        }
                    }
                }
            }
        }
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
