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
use ipc_broker::client::ClientHandle;
use tokio::sync::mpsc::unbounded_channel;

use crate::{
    listener::PacketListenerBuilder, publisher::PublisherBuilder, webserver::WebServerBuilder,
};

pub const BIND_ADDR: &str = "0.0.0.0:5247";
const TLS_CERT: &str = "web/tls/cert.pem";
const TLS_KEY: &str = "web/tls/key.pem";

async fn wait_for_remote_object() -> Result<()> {
    let client = ClientHandle::connect().await?;

    log::info!("Waiting for rob . . .");
    client.wait_for_object("rob").await?;
    log::info!("rob has started . . .");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    logger::setup_logger();

    let name = env!("CARGO_PKG_NAME");
    let version = env!("CARGO_PKG_VERSION");
    log::info!("{name} has started v{version}...");

    wait_for_remote_object().await?;

    let (broadcaster_tx, broadcaster_rx) = unbounded_channel();
    let (shut_webserver_tx, shut_webserver_rx) = tokio::sync::watch::channel(false);
    let shutdown = Arc::new(AtomicBool::new(false));

    // Spawn the packet listener and transmit the BroadcastData into the Publisher
    let (packet_listener_handle, async_capture_handle) = PacketListenerBuilder::new()
        .load_device()?
        .detect_subnet()?
        .load_dns_resolver()?
        .transmitter_broadcast_data_channel(broadcaster_tx)
        .spawn()
        .await?;

    // Spawn the a publisher to receive the BroadcastData from the packet listener
    let publisher_handle = PublisherBuilder::new()
        .receiver_broadcast_data_channel(broadcaster_rx)
        .shutdown_flag(shutdown.clone())
        .connect_client()
        .await?
        .spawn()
        .await?;

    // Spawn a webserver to host to push the received BroadcastData from the Publisher into the browser
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
    // Stop the packet capturing thread properly
    async_capture_handle.stop();
    // Set to true to signal the Publisher task to exit properly.
    shutdown.store(true, Ordering::Relaxed);
    // Stop the webserver properly
    let _ = shut_webserver_tx.send(true);

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
