mod logger;
mod webserver;

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
use pnet::ipnetwork::IpNetwork;
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

/// Returns true if the IP is reserved (broadcast, network, multicast, loopback, etc.)
/// or private but **outside** the given subnet.
fn is_reserved_ip(ip: Ipv4Addr, subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
    // Built-in checks first
    if ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }

    // Compute network and broadcast manually
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let net_u32 = u32::from(subnet) & mask_u32;
    let broadcast_u32 = net_u32 | !mask_u32;

    // Network or broadcast addresses within this subnet
    if ip_u32 == net_u32 || ip_u32 == broadcast_u32 {
        return true;
    }

    // Private IPs outside this subnet — e.g. 10.x.x.x or 172.16.x.x while your subnet is 192.168.x.x
    if ip.is_private() && (ip_u32 & mask_u32) != net_u32 {
        return true;
    }

    false
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

/// Check if an IP is in the given subnet
fn ip_in_subnet(ip: Ipv4Addr, subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
    (u32::from(ip) & u32::from(mask)) == (u32::from(subnet) & u32::from(mask))
}

/// Compute the network address from IP and mask
fn network_address(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & u32::from(mask))
}

/// Common keywords and exclusions used to identify real network interfaces
const KEYWORDS: [&str; 10] = [
    "wi-fi", "wireless", "ethernet", "lan", "eth", "enp", "eno", "en", "wlp", "wlan",
];
const EXCLUDED: [&str; 8] = [
    "loopback",
    "virtual",
    "vmware",
    "npcap",
    "hyper-v",
    "bluetooth",
    "tunnel",
    "vpn",
];

/// Returns true if an interface/device name+desc matches known keywords
fn matches_keywords(name: &str, desc: &str) -> bool {
    let name = name.to_lowercase();
    let desc = desc.to_lowercase();
    KEYWORDS
        .iter()
        .any(|kw| name.contains(kw) || desc.contains(kw))
}

/// Returns true if an interface/device name+desc should be excluded
fn is_excluded(name: &str, desc: &str) -> bool {
    let name = name.to_lowercase();
    let desc = desc.to_lowercase();
    EXCLUDED
        .iter()
        .any(|ex| name.contains(ex) || desc.contains(ex))
}

/// Detect the active pcap device
pub fn find_active_device() -> Option<Device> {
    let devices = Device::list().ok()?;

    devices
        .iter()
        .find(|d| {
            let desc = d.desc.as_deref().unwrap_or("");
            !is_excluded(&d.name, desc) && matches_keywords(&d.name, desc)
        })
        .cloned()
        // fallback: any non-loopback device
        .or_else(|| {
            devices
                .iter()
                .find(|d| {
                    let desc = d.desc.as_deref().unwrap_or("");
                    !is_excluded(&d.name, desc) && !d.addresses.is_empty()
                })
                .cloned()
        })
}

/// Detect local IPv4 subnet from datalink interfaces
pub fn detect_local_subnet() -> Option<(Ipv4Addr, Ipv4Addr)> {
    let mut candidates = vec![];

    for iface in datalink::interfaces() {
        if is_excluded(&iface.name, &iface.description)
            || !matches_keywords(&iface.name, &iface.description)
        {
            continue;
        }

        for ip in iface.ips {
            if let IpNetwork::V4(net) = ip {
                log::info!("Detected interface: {}", iface.name);
                log::info!("   ↳ Description: {}", iface.description);
                log::info!("   ↳ Local IP: {}", net.ip());
                log::info!("   ↳ Subnet mask: {}", net.mask());
                candidates.push((iface.name.clone(), net.ip(), net.mask()));
            }
        }
    }

    // Prefer wired/wireless
    if let Some((name, ip, mask)) = candidates.iter().find(|(name, _, _)| {
        ["eth", "en", "wlp", "wlan"]
            .iter()
            .any(|kw| name.contains(kw))
    }) {
        log::info!("Selected primary interface: {name}");
        return Some((*ip, *mask));
    }

    // Fallback
    candidates.first().map(|(name, ip, mask)| {
        log::info!("Fallback interface: {name}");
        (*ip, *mask)
    })
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
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
    let packet_listener_handle = listen_packets(tx, shutdown.clone()).await;

    let (shut_webserver_tx, shut_webserver_rx) = tokio::sync::watch::channel(false);
    let webserver_handle = webserver::spawn_webserver(shut_webserver_rx).await;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_network_and_broadcast_addresses() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        // Network address
        assert!(is_reserved_ip(Ipv4Addr::new(192, 168, 1, 0), subnet, mask));

        // Broadcast address
        assert!(is_reserved_ip(
            Ipv4Addr::new(192, 168, 1, 255),
            subnet,
            mask
        ));

        // Valid unicast address (not reserved)
        assert!(!is_reserved_ip(
            Ipv4Addr::new(192, 168, 1, 100),
            subnet,
            mask
        ));
    }

    #[test]
    fn test_loopback_linklocal_multicast_unspecified() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        // Loopback
        assert!(is_reserved_ip(Ipv4Addr::new(127, 0, 0, 1), subnet, mask));

        // Link-local (APIPA)
        assert!(is_reserved_ip(Ipv4Addr::new(169, 254, 10, 5), subnet, mask));

        // Multicast
        assert!(is_reserved_ip(Ipv4Addr::new(224, 0, 0, 1), subnet, mask));

        // Unspecified (0.0.0.0)
        assert!(is_reserved_ip(Ipv4Addr::new(0, 0, 0, 0), subnet, mask));
    }

    #[test]
    fn test_private_outside_subnet() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        // Private IP inside same subnet — should NOT be reserved
        assert!(!is_reserved_ip(
            Ipv4Addr::new(192, 168, 1, 42),
            subnet,
            mask
        ));

        // Private IP from another subnet — should be reserved
        assert!(is_reserved_ip(Ipv4Addr::new(10, 0, 0, 5), subnet, mask));
        assert!(is_reserved_ip(Ipv4Addr::new(172, 16, 0, 5), subnet, mask));

        // Public IP — not reserved
        assert!(!is_reserved_ip(Ipv4Addr::new(8, 8, 8, 8), subnet, mask));
    }

    #[test]
    fn test_small_subnet_edge_case() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 252); // /30 -> only 4 addresses (0–3)
        // network=192.168.1.0, broadcast=192.168.1.3, usable: 1 & 2

        assert!(is_reserved_ip(Ipv4Addr::new(192, 168, 1, 0), subnet, mask)); // network
        assert!(is_reserved_ip(Ipv4Addr::new(192, 168, 1, 3), subnet, mask)); // broadcast
        assert!(!is_reserved_ip(Ipv4Addr::new(192, 168, 1, 1), subnet, mask)); // valid
        assert!(!is_reserved_ip(Ipv4Addr::new(192, 168, 1, 2), subnet, mask)); // valid
    }
}
