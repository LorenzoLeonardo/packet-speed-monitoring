use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

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

#[derive(Default, Serialize, Deserialize, Debug)]
struct SpeedInfo {
    ip: String,
    dspeed: f64,
    uspeed: f64,
}

async fn listen_packets(
    tx: UnboundedSender<SpeedInfo>,
    shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    let device = Device::lookup().expect("No device found").unwrap();
    println!("Sniffing on device: {:?}", device.name);
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

        loop {
            if shutdown.load(Ordering::Relaxed) {
                eprintln!("shutdown requested: exiting pcap loop");
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

            if last.elapsed() >= Duration::from_millis(500) {
                println!("--- Traffic Report ---");
                for (ip, s) in stats.iter_mut() {
                    let up_mbps = (s.upload_bytes as f64 * 8.0) / 1_000_000.0;
                    let down_mbps = (s.download_bytes as f64 * 8.0) / 1_000_000.0;
                    if up_mbps > 0.01 || down_mbps > 0.01 {
                        println!(
                            "{ip} => Upload: {up_mbps:.2} Mbps | Download: {down_mbps:.2} Mbps"
                        );
                        let _ = tx.send(SpeedInfo {
                            ip: ip.to_string(),
                            dspeed: down_mbps,
                            uspeed: up_mbps,
                        });
                    }
                    s.upload_bytes = 0;
                    s.download_bytes = 0;
                }
                last = Instant::now();
            }
        }
        println!("[listen_packets] pcap thread exiting cleanly");
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
                eprintln!("shutdown requested: exiting pcap loop");
                break;
            }
            match rx.recv().await {
                Some(val) => {
                    println!("signal received: {val:?}");
                    let value = serde_json::to_value(&val).unwrap();
                    let _ = client
                        .publish("application.lan.speed", "speedInfo", &value)
                        .await;
                }
                None => {
                    println!("[publish_speed_info] rx channel closed, exiting...");
                    break;
                }
            }
        }
    }))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    println!("[packet-speed-monitoring] Started.");
    let (tx, rx) = unbounded_channel();
    let shutdown = Arc::new(AtomicBool::new(false));

    let publisher_handle = publish_speed_info(rx, shutdown.clone()).await?;
    let packet_listener_handle = listen_packets(tx, shutdown.clone()).await;

    println!("Sniffer started. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;
    println!("Ctrl+C received — shutting down...");

    shutdown.store(true, Ordering::Relaxed);

    // wait for blocking thread to end
    let _ = packet_listener_handle.await;
    let _ = publisher_handle.await;

    println!("[packet-speed-monitoring] Ended.");
    Ok(())
}
