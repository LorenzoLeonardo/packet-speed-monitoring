use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_dns_lookup::AsyncDnsResolver;
use async_pcap::{AsyncCapture, AsyncCaptureHandle, Capture, Device, Error, Packet};
use etherparse::Ipv4HeaderSlice;
use tokio::sync::mpsc::UnboundedSender;

use crate::monitor::device::DeviceInfo;
use crate::monitor::hostname::HostnameManager;
use crate::monitor::mac::MacManager;
use crate::monitor::publisher::BroadcastData;
use crate::monitor::speed_info::{self, SpeedInfo, Stats};

const SNAPLEN_SPEED_MONITOR: i32 = 1024;
const PACKET_SPEED_POLL_DELAY_MS: u64 = 1000;
const CAPTURE_TIMEOUT_MS: i32 = 500;
const MAC_CACHE_FILE: &str = "packet-speed-monitoring-mac-cache.json";

/// Builder for configuring and running the packet listener
pub struct PacketListenerBuilder {
    device: DeviceInfo,
    hostname_mgr: Option<HostnameManager>,
    broadcaster_tx: Option<UnboundedSender<Vec<BroadcastData>>>,
}

impl PacketListenerBuilder {
    /// Start a new builder
    pub fn new(device: DeviceInfo) -> Self {
        Self {
            device,
            hostname_mgr: None,
            broadcaster_tx: None,
        }
    }

    /// Create a default DNS resolver if not provided
    pub fn init_hostname_manager(mut self) -> Self {
        self.hostname_mgr = Some(HostnameManager::new(AsyncDnsResolver::new()));
        self
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
        let hostname_mgr: HostnameManager = self.hostname_mgr.context("Missing DNS resolver")?;
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
                run_capture_loop(async_capture, &hostname_mgr, subnet, mask, broadcaster_tx).await
            }),
            async_handle,
        ))
    }
}

/// Core capture loop
async fn run_capture_loop(
    cap: AsyncCapture,
    hostname_mgr: &HostnameManager,
    subnet: Ipv4Addr,
    mask: Ipv4Addr,
    broadcaster_tx: UnboundedSender<Vec<BroadcastData>>,
) {
    log::info!("[listener] packet listener task started.");
    let mut stats: HashMap<Ipv4Addr, Stats> = HashMap::new();
    let mut mac_mgr = MacManager::load_or_new(MAC_CACHE_FILE, Duration::from_secs(60)).await; // 1 min TTL
    let mut max_speeds: HashMap<Ipv4Addr, SpeedInfo> = HashMap::new();
    let delay = get_poll_delay();
    let mut last = Instant::now();

    while let Some(packet) = cap.next_packet().await {
        if let Err(e) = process_next_packet(
            packet,
            &subnet,
            &mask,
            &mut stats,
            hostname_mgr,
            &mut mac_mgr,
        )
        .await
        {
            log::debug!("Packet processing error: {e}");
        }
        let last_elapsed = last.elapsed();
        if last_elapsed >= Duration::from_millis(delay) {
            broadcast_stats(
                &mut stats,
                &mut max_speeds,
                hostname_mgr,
                &broadcaster_tx,
                last_elapsed,
                &mac_mgr,
            )
            .await;
            last = Instant::now();
            mac_mgr.prune_expired();
            mac_mgr
                .save_to_file(MAC_CACHE_FILE)
                .await
                .unwrap_or_else(|e| {
                    log::error!("Failed to save MAC cache: {e}");
                });
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
    hostname_mgr: &HostnameManager,
    mac_mgr: &mut MacManager,
) -> Result<(), async_pcap::Error> {
    match packet {
        Ok(packet) => {
            if packet.data.len() > 14 {
                // Extract source MAC from Ethernet frame

                if let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..]) {
                    // Update MAC cache
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&packet.data[6..12]);
                    mac_mgr.update(ip.source_addr(), mac, *subnet, *mask);
                    hostname_mgr.update_from_dhcp(&packet).await;
                    speed_info::update_stats(
                        ip.source_addr(),
                        ip.destination_addr(),
                        packet.header.len as usize,
                        stats,
                        subnet,
                        mask,
                    );
                }
            }
            Ok(())
        }
        Err(async_pcap::Error::TimeoutExpired) => Ok(()),
        Err(e) => Err(e),
    }
}

async fn broadcast_stats(
    stats: &mut HashMap<Ipv4Addr, Stats>,
    max_speeds: &mut HashMap<Ipv4Addr, SpeedInfo>,
    hostname_mgr: &HostnameManager,
    broadcaster_tx: &UnboundedSender<Vec<BroadcastData>>,
    elapsed_secs: Duration,
    mac_mgr: &MacManager,
) {
    let mut batch: Vec<BroadcastData> = Vec::new();

    for (ip, s) in stats.iter_mut() {
        let up_mbps = (s.upload_bytes() as f64 * 8.0) / (1_000_000.0 * elapsed_secs.as_secs_f64());
        let down_mbps =
            (s.download_bytes() as f64 * 8.0) / (1_000_000.0 * elapsed_secs.as_secs_f64());

        hostname_mgr.update_from_dns(ip).await;

        let hostname = hostname_mgr.get_hostname(ip).await;
        let mac = mac_mgr
            .get_as_string(ip)
            .unwrap_or_else(|| String::from("Not Active"));
        let current = SpeedInfo::new(ip.to_string(), hostname, down_mbps, up_mbps, mac);
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
