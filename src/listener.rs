use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_dns_lookup::AsyncDnsResolver;
use async_pcap::{AsyncCapture, AsyncCaptureHandle, Capture, Device, Error, Packet};
use etherparse::Ipv4HeaderSlice;
use tokio::sync::{Mutex, mpsc::UnboundedSender};

use crate::device::DeviceInfo;
use crate::publisher::BroadcastData;
use crate::speed_info::{self, SpeedInfo, Stats};

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
        let cap = Capture::from_device(device)
            .context("Failed to open capture from device")?
            .promisc(true)
            .snaplen(SNAPLEN_SPEED_MONITOR)
            .timeout(CAPTURE_TIMEOUT_MS)
            .open()
            .context("Failed to start async capture")?;
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
    let mut stats: HashMap<Ipv4Addr, Stats> = HashMap::new();
    let mut max_speeds: HashMap<Ipv4Addr, SpeedInfo> = HashMap::new();
    let hostname_cache = Arc::new(Mutex::new(HashMap::new()));
    let delay = get_poll_delay();
    let mut last = Instant::now();

    while let Some(packet) = cap.next_packet().await {
        if let Err(e) = process_next_packet(packet, &subnet, &mask, &mut stats).await {
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
    log::info!("[listener] capture thread exited cleanly");
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
) -> Result<(), async_pcap::Error> {
    match packet {
        Ok(packet) => {
            if packet.data.len() > 14
                && let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..])
            {
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
