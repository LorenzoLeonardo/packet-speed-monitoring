use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_dns_lookup::AsyncDnsResolver;
use async_pcap::{AsyncCapture, AsyncCaptureHandle, Capture, Device, Error, Packet};
use etherparse::{IpNumber, Ipv4HeaderSlice, UdpHeaderSlice};
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::monitor::device::DeviceInfo;
use crate::monitor::publisher::BroadcastData;
use crate::monitor::speed_info::{self, SpeedInfo, Stats};

const SNAPLEN_SPEED_MONITOR: i32 = 1024;
const PACKET_SPEED_POLL_DELAY_MS: u64 = 1000;
const CAPTURE_TIMEOUT_MS: i32 = 500;

/// Builder for configuring and running the packet listener
pub struct PacketListenerBuilder {
    device: DeviceInfo,
    dns: Option<AsyncDnsResolver>,
    broadcaster_tx: Option<UnboundedSender<Vec<BroadcastData>>>,
}

impl PacketListenerBuilder {
    /// Start a new builder
    pub fn new(device: DeviceInfo) -> Self {
        Self {
            device,
            dns: None,
            broadcaster_tx: None,
        }
    }

    /// Create a default DNS resolver if not provided
    pub fn load_dns_resolver(mut self) -> Result<Self> {
        let resolver = AsyncDnsResolver::new();
        self.dns = Some(resolver);
        Ok(self)
    }

    /// Set broadcast channel
    pub fn transmitter_broadcast_data_channel(
        mut self,
        tx: UnboundedSender<Vec<BroadcastData>>,
    ) -> Self {
        self.broadcaster_tx = Some(tx);
        self
    }

    /// Finalize and start the listener
    pub async fn spawn(self) -> Result<(tokio::task::JoinHandle<()>, AsyncCaptureHandle)> {
        let subnet = self.device.network_ip;
        let mask = self.device.netmask;
        let dns = self.dns.context("Missing DNS resolver")?;
        let broadcaster_tx = self.broadcaster_tx.context("Missing broadcaster channel")?;
        let device = Device::try_from(&self.device)?;
        let cap = Capture::from_device(device)?
            .promisc(true)
            .snaplen(SNAPLEN_SPEED_MONITOR)
            .timeout(CAPTURE_TIMEOUT_MS)
            .open()?;
        let (async_capture, async_handle) = AsyncCapture::new(cap);
        Ok((
            tokio::spawn(async move {
                run_capture_loop(async_capture, dns, subnet, mask, broadcaster_tx).await
            }),
            async_handle,
        ))
    }
}

/// Core capture loop
async fn run_capture_loop(
    cap: AsyncCapture,
    dns: AsyncDnsResolver,
    subnet: Ipv4Addr,
    mask: Ipv4Addr,
    broadcaster_tx: UnboundedSender<Vec<BroadcastData>>,
) {
    log::info!("[listener] packet listener task started.");
    let mut stats: HashMap<Ipv4Addr, Stats> = HashMap::new();
    let mut max_speeds: HashMap<Ipv4Addr, SpeedInfo> = HashMap::new();
    let hostname_cache = Arc::new(Mutex::new(HashMap::new()));
    let delay = get_poll_delay();
    let mut last = Instant::now();

    while let Some(packet) = cap.next_packet().await {
        if let Err(e) =
            process_next_packet(packet, &subnet, &mask, &mut stats, &hostname_cache).await
        {
            log::debug!("Packet processing error: {e}");
        }
        let last_elapsed = last.elapsed();
        if last_elapsed >= Duration::from_millis(delay) {
            broadcast_stats(
                dns.clone(),
                &mut stats,
                &mut max_speeds,
                &hostname_cache,
                &broadcaster_tx,
                last_elapsed,
            )
            .await;
            last = Instant::now();
        }
    }
    log::info!("[listener] packet listener task ended.");
}

fn get_poll_delay() -> u64 {
    std::env::var("PACKET_SPEED_POLL_DELAY_MS")
        .unwrap_or(PACKET_SPEED_POLL_DELAY_MS.to_string())
        .parse()
        .unwrap_or(PACKET_SPEED_POLL_DELAY_MS)
}

async fn process_next_packet(
    packet: Result<Packet, Error>,
    subnet: &Ipv4Addr,
    mask: &Ipv4Addr,
    stats: &mut HashMap<Ipv4Addr, Stats>,
    hostname_cache: &Arc<Mutex<HashMap<Ipv4Addr, String>>>,
) -> Result<(), async_pcap::Error> {
    match packet {
        Ok(packet) => {
            if packet.data.len() > 14
                && let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..])
            {
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
                                        log::info!(
                                            "DHCP REQUEST from {src_ip} (hostname: Some({host}))"
                                        );
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

                speed_info::update_stats(
                    ip.source_addr(),
                    ip.destination_addr(),
                    packet.header.len as usize,
                    stats,
                    subnet,
                    mask,
                );
            }
            Ok(())
        }
        Err(async_pcap::Error::TimeoutExpired) => Ok(()),
        Err(e) => Err(e),
    }
}

async fn broadcast_stats(
    dns: AsyncDnsResolver,
    stats: &mut HashMap<Ipv4Addr, Stats>,
    max_speeds: &mut HashMap<Ipv4Addr, SpeedInfo>,
    hostname_cache: &Arc<Mutex<HashMap<Ipv4Addr, String>>>,
    broadcaster_tx: &UnboundedSender<Vec<BroadcastData>>,
    elapsed_secs: Duration,
) {
    let mut batch: Vec<BroadcastData> = Vec::new();

    for (ip, s) in stats.iter_mut() {
        let up_mbps = (s.upload_bytes() as f64 * 8.0) / (1_000_000.0 * elapsed_secs.as_secs_f64());
        let down_mbps =
            (s.download_bytes() as f64 * 8.0) / (1_000_000.0 * elapsed_secs.as_secs_f64());

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

        let current = SpeedInfo::new(ip.to_string().as_str(), &hostname, down_mbps, up_mbps);
        speed_info::update_max_speed_local(max_speeds, &current);
        let max = max_speeds
            .get(ip)
            .cloned()
            .unwrap_or_else(|| current.clone());
        batch.push(BroadcastData::new(current, max));

        s.reset();
    }

    if !batch.is_empty()
        && let Err(e) = broadcaster_tx.send(batch)
    {
        log::warn!("{e}");
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
