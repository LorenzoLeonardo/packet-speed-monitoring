use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use async_dns_lookup::AsyncDnsResolver;
use async_pcap::Packet;
use etherparse::{IpNumber, Ipv4HeaderSlice, UdpHeaderSlice};
use tokio::sync::Mutex;

pub async fn update_hostname_cache_from_dns(
    ip: &Ipv4Addr,
    dns: AsyncDnsResolver,
    hostname_cache: &Arc<Mutex<HashMap<Ipv4Addr, String>>>,
) -> String {
    let hostname = {
        let cache_guard = hostname_cache.lock().await;
        cache_guard
            .get(ip)
            .cloned()
            .unwrap_or_else(|| ip.to_string())
    };

    if hostname == ip.to_string() {
        let hostname_cache = hostname_cache.clone();
        let ip_copy = *ip;
        let dns_inner = dns.clone();
        tokio::spawn(async move {
            let _ = get_or_resolve_hostname(dns_inner, ip_copy, hostname_cache).await;
        });
    }
    hostname
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

pub async fn update_hostname_cache_from_dhcp(
    packet: &Packet,
    hostname_cache: &Arc<Mutex<HashMap<Ipv4Addr, String>>>,
) {
    if packet.data.len() > 14
        && let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..])
    {
        let src_ip = &ip.source_addr();
        // Identify IP address
        let hostname = {
            let cache_guard = hostname_cache.lock().await;
            cache_guard
                .get(src_ip)
                .cloned()
                .unwrap_or_else(|| src_ip.to_string())
        };
        // If hostname is already known, skip DHCP parsing
        if hostname != src_ip.to_string() {
            return;
        }
        // Identify UDP layer
        if ip.protocol() == IpNumber::UDP {
            let ip_header_len = ip.slice().len();
            let transport_data = &packet.data[14 + ip_header_len..];
            let mut src_port = 0;
            let mut dst_port = 0;
            let src_ip = ip.source_addr();
            if let Ok(udp) = UdpHeaderSlice::from_slice(transport_data) {
                src_port = udp.source_port();
                dst_port = udp.destination_port();
            }
            // DHCP client sends from port 68, server 67
            if (src_port == 68 || dst_port == 68 || src_port == 67 || dst_port == 67)
                && transport_data.len() >= 8
            {
                let udp_payload = &transport_data[8..];
                let msg_type = extract_dhcp_message_type(udp_payload);

                if let Some(msg_type) = msg_type {
                    match msg_type {
                        1 => log::info!(
                            "DHCP DISCOVER from {src_ip} (hostname: {:?})",
                            extract_dhcp_hostname(udp_payload)
                        ),
                        3 => {
                            // DHCP REQUEST
                            if let Some(host) = extract_dhcp_hostname(udp_payload) {
                                log::info!("DHCP REQUEST from {src_ip} (hostname: Some({host}))");
                                let mut cache_guard = hostname_cache.lock().await;
                                cache_guard.insert(src_ip, host);
                            } else {
                                log::info!("DHCP REQUEST from {src_ip} (hostname: None)");
                            }
                        }
                        2 | 5 => {
                            if let Some(host) = extract_dhcp_hostname(udp_payload)
                                && let Some(ip_offered) = extract_dhcp_yiaddr(udp_payload)
                            {
                                log::info!(
                                    "DHCP {} from {src_ip} => {host} (offered IP: {ip_offered})",
                                    if msg_type == 2 { "OFFER" } else { "ACK" }
                                );
                                let mut cache_guard = hostname_cache.lock().await;
                                cache_guard.insert(ip_offered, host);
                            }
                        }
                        7 => {
                            log::info!(
                                "⚫ DHCP RELEASE from {src_ip} (hostname: {:?})",
                                extract_dhcp_hostname(udp_payload)
                            );
                        }
                        _ => {
                            log::warn!("Unhandled message type: {msg_type}");
                        }
                    }
                }
            }
        }
    }
}

fn extract_dhcp_hostname(payload: &[u8]) -> Option<String> {
    // Basic DHCP parsing: skip BOOTP fixed header (236 bytes) then options
    if payload.len() < 240 {
        return None;
    } // not enough
    // BOOTP header is 236; options start at offset 240 (after magic cookie)
    let opts = &payload[240..];
    let mut i = 0;
    while i < opts.len() {
        let opt = opts[i];
        if opt == 0xff {
            break;
        } // end
        if opt == 0x00 {
            i += 1;
            continue;
        } // pad
        if i + 1 >= opts.len() {
            break;
        }
        let len = opts[i + 1] as usize;
        if i + 2 + len > opts.len() {
            break;
        }
        if opt == 12 {
            // Host Name option
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
    // DHCP options start after the 240-byte fixed header
    let mut i = 240;
    while i + 2 < payload.len() {
        let option_type = payload[i];
        if option_type == 255 {
            break; // End option
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
