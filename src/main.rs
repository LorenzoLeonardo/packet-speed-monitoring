mod device;
mod helpers;
mod listener;
mod logger;
mod monitor;
mod publisher;
mod signal;
mod speed_info;
mod webserver;

use anyhow::Result;
use ipc_broker::client::ClientHandle;

use crate::{monitor::PacketMonitor, webserver::WebServerBuilder};

pub const BIND_ADDR: &str = "0.0.0.0:5247";
const TLS_CERT: &str = "web/tls/cert.pem";
const TLS_KEY: &str = "web/tls/key.pem";

async fn wait_for_remote_object(handle: &ClientHandle) -> Result<()> {
    log::info!("Waiting for rob . . .");
    handle.wait_for_object("rob").await?;
    log::info!("rob has started . . .");
    Ok(())
}

struct LogStart;

impl LogStart {
    pub fn start() -> Self {
        logger::setup_logger();

        log::info!(
            "{} v{} has started.",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        Self
    }
}

impl Drop for LogStart {
    fn drop(&mut self) {
        log::info!(
            "{} v{} has ended.",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _log = LogStart::start();
    let client = ClientHandle::connect().await?;
    wait_for_remote_object(&client).await?;

    let packet_monitor_handler = PacketMonitor::start(client.clone()).await?;

    // Spawn a webserver to host to push the received BroadcastData from the Publisher into the browser
    let webserver_handler = WebServerBuilder::new(client)
        .bind_addr(BIND_ADDR)
        .cert_paths(TLS_CERT, TLS_KEY)
        .spawn()
        .await?;

    // wait here until signal is sent
    signal::wait_until_signal().await;

    // Stop the packet capturing thread properly
    packet_monitor_handler.stop();
    // Stop the webserver properly
    webserver_handler.stop();

    // wait for blocking thread to end
    let (result1, result2) = tokio::join!(packet_monitor_handler.handle, webserver_handler.handle);

    for (i, res) in [result1, result2].into_iter().enumerate() {
        if let Err(e) = res {
            log::error!("Task {i} failed: {e}");
        }
    }
    Ok(())
}
