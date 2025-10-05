mod logger;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use chrono::{FixedOffset, Local, Offset, Utc};
use etherparse::Ipv4HeaderSlice;
use ipc_broker::client::ClientHandle;
use pcap::{Capture, Device};
use pnet::datalink;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::{self, JoinHandle};

#[derive(Default)]
struct Stats {
    upload_bytes: usize,
    download_bytes: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct SpeedInfo {
    ip: String,
    mbps_down: f64,
    mbps_up: f64,
    time_local: String,
    time_utc: String,
    timezone: String,
}

impl SpeedInfo {
    pub fn new(ip: &str, down: f64, up: f64) -> Self {
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
            mbps_down: down,
            mbps_up: up,
            time_local: local_time_str,
            time_utc: timestamp.to_rfc3339(),
            timezone,
        }
    }
}

/// Detect local IPv4 address and subnet mask (first non-loopback interface)
fn detect_local_subnet() -> Option<(Ipv4Addr, Ipv4Addr)> {
    for iface in datalink::interfaces() {
        if iface.is_loopback() {
            continue;
        }
        for ip in iface.ips {
            if let pnet::ipnetwork::IpNetwork::V4(net) = ip {
                log::info!("Detected interface: {}", iface.name);
                log::info!("Local IP: {}", net.ip());
                log::info!("Subnet mask: {}", net.mask());
                return Some((net.ip(), net.mask()));
            }
        }
    }
    None
}

/// Check if an IP is in the given subnet
fn ip_in_subnet(ip: Ipv4Addr, subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
    (u32::from(ip) & u32::from(mask)) == (u32::from(subnet) & u32::from(mask))
}

/// Compute the network address from IP and mask
fn network_address(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & u32::from(mask))
}

async fn listen_packets(
    tx: UnboundedSender<SpeedInfo>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let device = find_active_device().expect("No device found");
    log::info!(
        "Sniffing on device: {} decscription: {:?}",
        device.name,
        device.desc
    );
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .timeout(500)
        .immediate_mode(true)
        .open()
        .unwrap();

    // Detect local subnet
    let (subnet, mask) = detect_local_subnet()
        .map(|(ip, mask)| (network_address(ip, mask), mask))
        .unwrap_or_else(|| {
            log::warn!("Could not detect local subnet, sending all IPs");
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(0, 0, 0, 0))
        });

    log::info!("Monitoring subnet: {subnet} Mask: {mask}");

    task::spawn_blocking(move || {
        let mut last = Instant::now();
        let mut stats = HashMap::<Ipv4Addr, Stats>::new();
        let delay: u64 = std::env::var("PACKET_SPEED_POLL_DELAY_MS")
            .unwrap_or(1000.to_string())
            .parse()
            .unwrap_or(1000);
        loop {
            if shutdown.load(Ordering::Relaxed) {
                log::info!("shutdown requested: exiting pcap loop");
                break;
            }

            match cap.next_packet() {
                Ok(packet) => {
                    if packet.data.len() > 14 {
                        if let Ok(ip) = Ipv4HeaderSlice::from_slice(&packet.data[14..]) {
                            let src = ip.source_addr();
                            let dst = ip.destination_addr();
                            let size = packet.header.len as usize;

                            // Filter only IPs within subnet
                            if ip_in_subnet(src, subnet, mask) {
                                stats.entry(src).or_default().upload_bytes += size;
                            }
                            if ip_in_subnet(dst, subnet, mask) {
                                stats.entry(dst).or_default().download_bytes += size;
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // nothing arrived this interval, continue
                }
                Err(e) => eprintln!("{e}"),
            }

            if last.elapsed() >= Duration::from_millis(delay) {
                let elapsed_secs = last.elapsed().as_secs_f64(); // exact elapsed time
                log::debug!("--- Traffic Report ---");
                for (ip, s) in stats.iter_mut() {
                    let up_mbps = (s.upload_bytes as f64 * 8.0) / (1_000_000.0 * elapsed_secs);
                    let down_mbps = (s.download_bytes as f64 * 8.0) / (1_000_000.0 * elapsed_secs);
                    log::debug!(
                        "{ip} => Upload: {up_mbps:.2} Mbps | Download: {down_mbps:.2} Mbps"
                    );
                    let _ = tx.send(SpeedInfo::new(ip.to_string().as_str(), down_mbps, up_mbps));
                    s.upload_bytes = 0;
                    s.download_bytes = 0;
                }
                last = Instant::now();
            }
        }
        log::info!("[listen_packets] pcap thread exiting cleanly");
    })
}

async fn publish_speed_info(
    mut rx: UnboundedReceiver<SpeedInfo>,
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

pub fn find_active_device() -> Option<Device> {
    // List all available devices
    let devices = Device::list().ok()?;

    // Common keywords found in active interfaces
    let keywords = [
        "wi-fi", "wireless", "ethernet", "lan", "eth", "enp", "eno", "en", "wlp", "wlan",
    ];

    // Exclude virtual, loopback, or VPN adapters
    let excluded = [
        "loopback",
        "virtual",
        "vmware",
        "npcap",
        "hyper-v",
        "bluetooth",
        "tunnel",
        "vpn",
    ];

    // Helper to check if a device matches a keyword
    let matches_keywords = |desc: &str, name: &str| {
        let desc_l = desc.to_lowercase();
        let name_l = name.to_lowercase();
        keywords
            .iter()
            .any(|kw| desc_l.contains(kw) || name_l.contains(kw))
    };

    // Helper to check if a device should be excluded
    let is_excluded = |desc: &str, name: &str| {
        let desc_l = desc.to_lowercase();
        let name_l = name.to_lowercase();
        excluded
            .iter()
            .any(|ex| desc_l.contains(ex) || name_l.contains(ex))
    };

    // Step 1: Prefer devices that match known patterns and are not excluded
    if let Some(dev) = devices.iter().find(|d| {
        let desc = d.desc.as_deref().unwrap_or("");
        !is_excluded(desc, &d.name) && matches_keywords(desc, &d.name)
    }) {
        return Some(dev.clone());
    }

    // Step 2: Prefer any non-loopback, non-virtual device with addresses
    if let Some(dev) = devices.iter().find(|d| {
        let desc = d.desc.as_deref().unwrap_or("");
        !is_excluded(desc, &d.name) && !d.addresses.is_empty()
    }) {
        return Some(dev.clone());
    }

    // Step 3: As a last resort, return the first non-loopback device
    devices.into_iter().find(|d| {
        let desc = d.desc.as_deref().unwrap_or("");
        !is_excluded(desc, &d.name)
    })
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    logger::setup_logger();

    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    log::info!("{name} has started v{version}...");

    let (tx, rx) = unbounded_channel();
    let shutdown = Arc::new(AtomicBool::new(false));

    let publisher_handle = publish_speed_info(rx, shutdown.clone()).await?;
    let packet_listener_handle = listen_packets(tx, shutdown.clone()).await;

    log::info!("Sniffer started. Press Ctrl+C to stop.");

    // wait here until signal is sent
    wait_until_signal().await;

    // Set to true to signal the task to exit properly
    shutdown.store(true, Ordering::Relaxed);

    // wait for blocking thread to end
    let (result1, result2) = tokio::join!(packet_listener_handle, publisher_handle);

    for (i, res) in [result1, result2].into_iter().enumerate() {
        if let Err(e) = res {
            log::error!("Task {i} failed: {e}");
        }
    }
    log::info!("[packet-speed-monitoring] Ended.");
    Ok(())
}
