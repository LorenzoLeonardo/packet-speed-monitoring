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

async fn listen_packets(
    tx: UnboundedSender<SpeedInfo>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let device = Device::lookup().expect("No device found").unwrap();
    log::info!("Sniffing on device: {:?}", device.name);
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .open()
        .unwrap();

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

                            stats.entry(src).or_default().upload_bytes += size;
                            stats.entry(dst).or_default().download_bytes += size;
                        }
                    }
                }
                Err(e) => eprintln!("{e}"),
            }

            if last.elapsed() >= Duration::from_millis(delay) {
                log::debug!("--- Traffic Report ---");
                for (ip, s) in stats.iter_mut() {
                    let up_mbps = (s.upload_bytes as f64 * 8.0) / 1_000_000.0;
                    let down_mbps = (s.download_bytes as f64 * 8.0) / 1_000_000.0;
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
