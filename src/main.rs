mod helpers;
mod listener;
mod logger;
mod publisher;
mod signal;
mod speed_info;
mod webserver;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use async_dns_lookup::AsyncDnsResolver;
use async_pcap::{AsyncCapture, Capture};
use ipc_broker::client::ClientHandle;
use tokio::sync::mpsc::unbounded_channel;

use crate::webserver::WebServerBuilder;

pub const BIND_ADDR: &str = "0.0.0.0:5247";
const SNAPLEN_SPEED_MONITOR: i32 = 1024;
const PACKET_SPEED_POLL_DELAY_MS: u64 = 1000;
const TLS_CERT: &str = "web/tls/cert.pem";
const TLS_KEY: &str = "web/tls/key.pem";

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

    let (broadcaster_tx, broadcaster_rx) = unbounded_channel();
    let shutdown = Arc::new(AtomicBool::new(false));

    let device = listener::find_device()?;
    let (network_ip, mask) = listener::get_subnet(&device)?;

    let cap = Capture::from_device(device)?
        .promisc(true)
        .snaplen(SNAPLEN_SPEED_MONITOR)
        .timeout(500)
        .immediate_mode(true)
        .open()?;

    // Run the capturing of the packet at the background
    let (cap, handle) = AsyncCapture::new(cap);
    let dns = AsyncDnsResolver::new();

    let publisher_handle = publisher::publish_speed_info(broadcaster_rx, shutdown.clone()).await?;
    let packet_listener_handle =
        listener::listen_packets(cap, dns, network_ip, mask, broadcaster_tx).await?;

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
    signal::wait_until_signal().await;
    let _ = shut_webserver_tx.send(true);
    // Set to true to signal the task to exit properly
    shutdown.store(true, Ordering::Relaxed);
    // Stop the packet capturing thread
    handle.stop();

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
