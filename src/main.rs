mod helpers;
mod logger;
mod manager;
mod monitor;
mod signal;
mod webserver;

use std::sync::Arc;

use anyhow::Result;
use ipc_broker::client::IPCClient;
use tokio::sync::Notify;

use crate::{logger::Log, manager::SystemManager};

const BIND_ADDR: &str = "0.0.0.0:5247";
const TLS_CERT: &str = "tls/cert.pem";
const TLS_KEY: &str = "tls/key.pem";

async fn wait_for_remote_object(handle: &IPCClient) -> Result<()> {
    log::info!("Waiting for rob . . .");
    handle.wait_for_object("rob").await?;
    log::info!("rob has started . . .");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let _log = Log::init();
    let client = IPCClient::connect().await?;
    // Trigger via process or triggered outside by the OS to stop the process properly.
    let manual_trigger = Arc::new(Notify::new());

    wait_for_remote_object(&client).await?;

    let handle = SystemManager::new(client, Arc::clone(&manual_trigger))
        .spawn()
        .await?;

    handle.start().await;
    // wait here until signal is sent
    signal::wait_until_signal(manual_trigger).await;
    handle.stop().await;
    Ok(())
}
