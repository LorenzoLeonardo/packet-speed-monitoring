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
use tokio::sync::mpsc::unbounded_channel;
use tokio::task;

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

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let device = Device::lookup().expect("No device found").unwrap();
    println!("Sniffing on device: {:?}", device.name);

    let client = ClientHandle::connect().await?;
    // Open capture (mutable because we'll set non-blocking)
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .immediate_mode(true)
        .open()
        .unwrap();

    // Shared shutdown flag
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_for_task = shutdown.clone();
    let (tx, mut rx) = unbounded_channel();

    // Move cap into the blocking task
    let handle = task::spawn_blocking(move || {
        let mut last = Instant::now();
        let mut stats = HashMap::<Ipv4Addr, Stats>::new();

        // cap is moved here and used in the blocking threadpool
        loop {
            // If main signaled shutdown, break out
            if shutdown_for_task.load(Ordering::Relaxed) {
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
                Err(e) => {
                    eprintln!("{e}");
                }
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
                        if let Err(e) = tx.send(SpeedInfo {
                            ip: ip.to_string(),
                            dspeed: down_mbps,
                            uspeed: up_mbps,
                        }) {
                            eprintln!("{e}");
                        }
                    }
                    s.upload_bytes = 0;
                    s.download_bytes = 0;
                }
                last = Instant::now();
            }
        }
        // any cleanup here
        println!("pcap thread exiting cleanly");
    });

    let (oneshot_tx, mut oneshot_rx) = unbounded_channel();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Some(val) => {
                            println!("signal received: {val:?}");
                            let value = serde_json::to_value(&val).unwrap();
                            let _ = client
                                .publish("application.lan.speed", "speedInfo", &value)
                                .await;
                        }
                        None => {
                            println!("rx channel closed, exiting...");
                            break;
                        }
                    }
                }
                Some(flag) = oneshot_rx.recv() => {
                    if flag {
                        println!("Exit tokio::select");
                        break;
                    }
                }
            }
        }
    });

    println!("Sniffer started. Press Ctrl+C to stop.");

    // Wait for Ctrl+C on the main runtime thread
    tokio::signal::ctrl_c().await?;
    println!("Ctrl+C received — shutting down...");

    // signal the blocking task to stop and await it
    shutdown.store(true, Ordering::Relaxed);
    // exit the tokio::select
    let _ = oneshot_tx.send(true);
    // wait for the blocking task to finish
    let _ = handle.await;

    println!("Exited.");
    Ok(())
}
