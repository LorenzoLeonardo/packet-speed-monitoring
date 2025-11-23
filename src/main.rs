mod helpers;
mod logger;
mod manager;
mod monitor;
mod signal;
mod webserver;

use std::sync::Arc;

use anyhow::Result;
use curl_http_client::{Collector, dep::async_curl::CurlActor};
use ipc_broker::client::IPCClient;
use tokio::{
    runtime::Builder,
    sync::{Notify, broadcast},
};

use crate::{logger::Log, manager::SystemManager};

const BIND_ADDR: &str = "0.0.0.0:5247";
const TLS_CERT: &str = "tls/cert.pem";
const TLS_KEY: &str = "tls/key.pem";
const LOG_FILE: &str = "log.txt";

async fn wait_for_remote_object(handle: &IPCClient) -> Result<()> {
    log::info!("Waiting for rob . . .");
    handle.wait_for_object("rob").await?;
    log::info!("rob has started . . .");
    Ok(())
}

async fn run_app(
    sse_log_tx: broadcast::Sender<String>,
    curl_actor: CurlActor<Collector>,
) -> Result<()> {
    let client = IPCClient::connect().await?;
    // Trigger via process or triggered outside by the OS to stop the process properly.
    let manual_trigger = Arc::new(Notify::new());

    wait_for_remote_object(&client).await?;

    let handle = SystemManager::new(client, Arc::clone(&manual_trigger), sse_log_tx)
        .spawn(curl_actor)
        .await?;

    // wait here until signal is sent
    signal::wait_until_signal(manual_trigger).await;
    handle.stop().await;
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let curl_actor = CurlActor::new_runtime(Builder::new_multi_thread().enable_all().build()?);
    // Initialize the logger, lets panic if it fails intentionally
    // It mean disk is full or permission issue
    let log = Log::init().await.unwrap();
    let sse_log_tx = log.tx.clone();
    let res = run_app(sse_log_tx, curl_actor).await;

    log.shutdown().await;
    res
}
