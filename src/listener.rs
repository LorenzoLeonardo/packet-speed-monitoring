use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_dns_lookup::AsyncDnsResolver;
use async_pcap::{AsyncCapture, Error, Packet};
use etherparse::Ipv4HeaderSlice;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;

use crate::PACKET_SPEED_POLL_DELAY_MS;
use crate::helpers::{detect_local_subnet, find_active_device, network_address};
use crate::publisher::BroadcastData;
use crate::speed_info::{self, SpeedInfo, Stats};

// Main entry
pub async fn listen_packets(
    cap: AsyncCapture,
    dns: AsyncDnsResolver,
    broadcaster_tx: UnboundedSender<Vec<BroadcastData>>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let (subnet, mask) = detect_subnet();

    Ok(tokio::spawn(async move {
        run_capture_loop(cap, dns, subnet, mask, broadcaster_tx).await
    }))
}

/// Find the active device
pub fn find_device() -> anyhow::Result<async_pcap::Device> {
    let device = find_active_device().context("No active device found")?;
    log::info!(
        "Sniffing on device: {} description: {:?}",
        device.name,
        device.desc
    );
    Ok(device)
}

/// Detect local subnet
fn detect_subnet() -> (Ipv4Addr, Ipv4Addr) {
    detect_local_subnet()
        .map(|(ip, mask)| (network_address(ip, mask), mask))
        .unwrap_or_else(|| {
            log::warn!("Could not detect local subnet, sending all IPs");
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0))
        })
}

/// Run the blocking packet capture loop
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
    log::info!("[listener] pcap thread exiting cleanly");
}

/// Get polling delay from environment
fn get_poll_delay() -> u64 {
    std::env::var("PACKET_SPEED_POLL_DELAY_MS")
        .unwrap_or(PACKET_SPEED_POLL_DELAY_MS.to_string())
        .parse()
        .unwrap_or(PACKET_SPEED_POLL_DELAY_MS)
}

/// Process a single packet
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

/// Broadcast current stats
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

/// Asynchronous, cached reverse DNS lookup
async fn get_or_resolve_hostname(
    dns: AsyncDnsResolver,
    ip: Ipv4Addr,
    cache: Arc<Mutex<HashMap<Ipv4Addr, String>>>,
) -> String {
    // Quick read lock first — avoid re-resolving
    {
        let cache_guard = cache.lock().await;
        if let Some(name) = cache_guard.get(&ip) {
            return name.clone();
        }
    }

    // Do reverse lookup in blocking thread
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

    // Cache result
    let mut cache_guard = cache.lock().await;
    cache_guard.insert(ip, hostname.clone());

    hostname
}
