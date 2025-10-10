mod helpers;
mod logger;
mod webserver;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{FixedOffset, Local, Offset, Utc};
use etherparse::Ipv4HeaderSlice;
use ipc_broker::client::ClientHandle;
use pcap::Capture;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::{self, JoinHandle};

use crate::helpers::{
    detect_local_subnet, find_active_device, ip_in_subnet, is_reserved_ip, network_address,
};
use crate::webserver::WebServerBuilder;

pub const BIND_ADDR: &str = "0.0.0.0:5247";
const SNAPLEN_SPEED_MONITOR: i32 = 1024;
const PACKET_SPEED_POLL_DELAY_MS: u64 = 1000;
const TLS_CERT: &str = "web/tls/cert.pem";
const TLS_KEY: &str = "web/tls/key.pem";

#[derive(Default)]
struct Stats {
    upload_bytes: usize,
    download_bytes: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SpeedInfo {
    ip: String,
    hostname: String,
    mbps_down: f64,
    mbps_up: f64,
    time_local: String,
    time_utc: String,
    timezone: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct BroadcastData {
    current: SpeedInfo,
    max: SpeedInfo,
}

/// Update in-memory max speeds (per IP)
fn update_max_speed_local(map: &mut HashMap<Ipv4Addr, SpeedInfo>, data: &SpeedInfo) {
    // If IP fails to parse, skip the update (avoid inserting 0.0.0.0 entries)
    let ip: Ipv4Addr = match data.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return,
    };

    match map.entry(ip) {
        Entry::Occupied(mut e) => {
            let max = e.get_mut();
            let mut changed = false;

            // Update download max independently
            if data.mbps_down > max.mbps_down {
                max.mbps_down = data.mbps_down;
                max.time_local = data.time_local.clone();
                max.time_utc = data.time_utc.clone();
                max.timezone = data.timezone.clone();
                changed = true;
            }

            // Update upload max independently
            if data.mbps_up > max.mbps_up {
                max.mbps_up = data.mbps_up;
                // Use the same timestamp fields to mark when upload max happened.
                // If you want separate timestamps for up/down, see note below.
                max.time_local = data.time_local.clone();
                max.time_utc = data.time_utc.clone();
                max.timezone = data.timezone.clone();
                changed = true;
            }

            if changed {
                log::debug!(
                    "Updated max for {} => down: {:.6}, up: {:.6}",
                    data.ip,
                    max.mbps_down,
                    max.mbps_up
                );
            }
        }
        Entry::Vacant(e) => {
            e.insert(data.clone());
            log::debug!(
                "Inserted new max record for {} => down: {:.6}, up: {:.6}",
                data.ip,
                data.mbps_down,
                data.mbps_up
            );
        }
    }
}

impl SpeedInfo {
    pub fn new(ip: &str, hostname: &str, down: f64, up: f64) -> Self {
        let timestamp = Utc::now();
        let local_time = Local::now();

        // Compute offset between local time and UTC
        let offset_seconds = local_time.offset().fix().local_minus_utc();
        let hours = offset_seconds / 3600;
        let minutes = (offset_seconds.abs() % 3600) / 60;

        let sign = if offset_seconds >= 0 { '+' } else { '-' };
        let timezone = format!("UTC{}{:02}:{:02}", sign, hours.abs(), minutes);

        // Create FixedOffset and convert UTC → local
        let fixed_offset =
            FixedOffset::east_opt(offset_seconds).unwrap_or(FixedOffset::east_opt(0).unwrap());
        let local_time_str = timestamp.with_timezone(&fixed_offset).to_rfc3339();

        Self {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            mbps_down: down,
            mbps_up: up,
            time_local: local_time_str,
            time_utc: timestamp.to_rfc3339(),
            timezone,
        }
    }
}

/// Asynchronous, cached reverse DNS lookup
async fn get_or_resolve_hostname(
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
    let resolved = tokio::task::spawn_blocking(move || reverse_lookup(&ip))
        .await
        .unwrap_or_else(|_| Err(io::Error::other("join error")));

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

/// Blocking reverse DNS
fn reverse_lookup(ip: &Ipv4Addr) -> io::Result<String> {
    use dns_lookup::getnameinfo;
    let sa = SocketAddr::new(IpAddr::V4(*ip), 0);
    let host = getnameinfo(&sa, 0)?;
    Ok(host.0)
}

async fn listen_packets(
    tx: UnboundedSender<Vec<BroadcastData>>,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    let device = find_active_device().context("No active device found")?;
    log::info!(
        "Sniffing on device: {} description: {:?}",
        device.name,
        device.desc
    );
    let mut cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(SNAPLEN_SPEED_MONITOR)
        .timeout(500)
        .immediate_mode(true)
        .open()?;

    // Detect local subnet
    let (subnet, mask) = detect_local_subnet()
        .map(|(ip, mask)| (network_address(ip, mask), mask))
        .unwrap_or_else(|| {
            log::warn!("Could not detect local subnet, sending all IPs");
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0))
        });

    log::info!("Monitoring subnet: {subnet} Mask: {mask}");

    Ok(task::spawn_blocking(move || {
        let mut last = Instant::now();
        let mut stats = HashMap::<Ipv4Addr, Stats>::new();
        let mut max_speeds: HashMap<Ipv4Addr, SpeedInfo> = HashMap::new();
        let hostname_cache = Arc::new(Mutex::new(HashMap::new()));

        let delay: u64 = std::env::var("PACKET_SPEED_POLL_DELAY_MS")
            .unwrap_or(PACKET_SPEED_POLL_DELAY_MS.to_string())
            .parse()
            .unwrap_or(PACKET_SPEED_POLL_DELAY_MS);
        loop {
            if shutdown.load(Ordering::Relaxed) {
                log::info!("shutdown requested: exiting pcap loop");
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    if packet.data.len() > 14
                        && let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..])
                    {
                        let src = ip.source_addr();
                        let dst = ip.destination_addr();
                        let size = packet.header.len as usize;

                        // Filter only IPs within subnet
                        if ip_in_subnet(src, subnet, mask) && !is_reserved_ip(src, subnet, mask) {
                            stats.entry(src).or_default().upload_bytes += size;
                        }
                        if ip_in_subnet(dst, subnet, mask) && !is_reserved_ip(dst, subnet, mask) {
                            stats.entry(dst).or_default().download_bytes += size;
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    log::debug!("next_packet(): TimeoutExpired");
                }
                Err(e) => log::error!("{e}"),
            }

            let elapsed = last.elapsed(); // measure once
            if elapsed >= Duration::from_millis(delay) {
                let elapsed_secs = elapsed.as_secs_f64(); // exact elapsed time
                log::debug!("--- Traffic Report ---");
                // Create a vector to hold all data for this broadcast tick
                let mut batch: Vec<BroadcastData> = Vec::new();
                for (ip, s) in stats.iter_mut() {
                    let up_mbps = (s.upload_bytes as f64 * 8.0) / (1_000_000.0 * elapsed_secs);
                    let down_mbps = (s.download_bytes as f64 * 8.0) / (1_000_000.0 * elapsed_secs);
                    log::debug!(
                        "{ip} => Upload: {up_mbps:.2} Mbps | Download: {down_mbps:.2} Mbps"
                    );
                    //let hostname_cache = hostname_cache.clone();
                    // Try to get hostname from cache first
                    let hostname = {
                        let cache_guard = hostname_cache.blocking_lock();
                        cache_guard
                            .get(ip)
                            .cloned()
                            .unwrap_or_else(|| ip.to_string())
                    };
                    // Spawn background task to resolve if not cached
                    if hostname == ip.to_string() {
                        let hostname_cache = hostname_cache.clone();
                        let ip_inner = *ip;
                        tokio::spawn(async move {
                            let _ = get_or_resolve_hostname(ip_inner, hostname_cache).await;
                            // Cache is updated asynchronously
                        });
                    }

                    // Now you can safely create SpeedInfo
                    let current = SpeedInfo::new(&ip.to_string(), &hostname, down_mbps, up_mbps);

                    // update max and create broadcast packet
                    update_max_speed_local(&mut max_speeds, &current);
                    let max = max_speeds
                        .get(ip)
                        .cloned()
                        .unwrap_or_else(|| current.clone());

                    let broad_cast = BroadcastData { current, max };
                    log::trace!("{broad_cast:?}");
                    batch.push(broad_cast);

                    s.upload_bytes = 0;
                    s.download_bytes = 0;
                }
                // Send the entire batch once per interval
                if !batch.is_empty() {
                    log::trace!("Broadcasting {} entries", batch.len());
                    let _ = tx.send(batch);
                }
                last = Instant::now();
            }
        }
        log::info!("[listen_packets] pcap thread exiting cleanly");
    }))
}

async fn publish_speed_info(
    mut rx: UnboundedReceiver<Vec<BroadcastData>>,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, std::io::Error> {
    let client = ClientHandle::connect().await?;

    Ok(tokio::spawn(async move {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                log::info!("shutdown requested: exiting pcap loop");
                break;
            }
            match rx.recv().await {
                Some(val) => {
                    log::debug!("signal received: {val:?}");
                    if let Ok(value) = serde_json::to_value(&val) {
                        let _ = client
                            .publish("application.lan.speed", "speedInfo", &value)
                            .await;
                    } else {
                        log::error!("[publish_speed_info] parse error to Value.");
                        break;
                    }
                }
                None => {
                    log::info!("[publish_speed_info] rx channel closed, exiting...");
                    break;
                }
            }
        }
    }))
}

async fn wait_until_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        let mut int = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");

        tokio::select! {
            _ = term.recv() => {
                log::info!("Received SIGTERM (systemd stop).");
            }
            _ = int.recv() => {
                log::info!("Received SIGINT (Ctrl+C).");
            }
        }
    }

    #[cfg(windows)]
    {
        // On Windows, only Ctrl+C is supported directly
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        log::info!("Received Ctrl+C (Windows)");
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logger::setup_logger();

    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    log::info!("{name} has started v{version}...");

    let client = ClientHandle::connect().await?;

    log::info!("Waiting for rob . . .");
    client.wait_for_object("rob").await?;
    log::info!("rob has started . . .");

    let (tx, rx) = unbounded_channel();
    let shutdown = Arc::new(AtomicBool::new(false));

    let publisher_handle = publish_speed_info(rx, shutdown.clone()).await?;
    let packet_listener_handle = listen_packets(tx, shutdown.clone()).await?;

    let (shut_webserver_tx, shut_webserver_rx) = tokio::sync::watch::channel(false);
    let webserver_handle = WebServerBuilder::new()
        .bind_addr(BIND_ADDR)
        .cert_paths(TLS_CERT, TLS_KEY)
        .shutdown(shut_webserver_rx)
        .build()
        .await?
        .spawn()
        .await?;

    log::info!("Sniffer started. Press Ctrl+C to stop.");

    // wait here until signal is sent
    wait_until_signal().await;
    let _ = shut_webserver_tx.send(true);
    // Set to true to signal the task to exit properly
    shutdown.store(true, Ordering::Relaxed);

    // wait for blocking thread to end
    let (result1, result2, result3) =
        tokio::join!(packet_listener_handle, publisher_handle, webserver_handle);

    for (i, res) in [result1, result2, result3].into_iter().enumerate() {
        if let Err(e) = res {
            log::error!("Task {i} failed: {e}");
        }
    }
    log::info!("[packet-speed-monitoring] Ended.");
    Ok(())
}
