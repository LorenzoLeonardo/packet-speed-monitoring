mod device;
mod helpers;
mod listener;
mod logger;
mod monitor;
mod publisher;
mod signal;
mod speed_info;
mod webserver;

use std::sync::Arc;

use anyhow::Result;
use ipc_broker::client::IPCClient;
use tokio::{
    sync::{
        Notify,
        mpsc::{self, Sender},
    },
    task::JoinHandle,
};

use crate::{
    monitor::PacketMonitor,
    webserver::{ControlMessage, WebServerBuilder, WebServerHandler},
};

pub const BIND_ADDR: &str = "0.0.0.0:5247";
const TLS_CERT: &str = "web/tls/cert.pem";
const TLS_KEY: &str = "web/tls/key.pem";

async fn wait_for_remote_object(handle: &IPCClient) -> Result<()> {
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

async fn control_manager(
    client: IPCClient,
    signal_handle: Arc<Notify>,
) -> (JoinHandle<()>, Sender<ControlMessage>) {
    let (control_tx, mut control_rx) = mpsc::channel::<ControlMessage>(8);
    // --- Spawn control background task ---
    let control_tx_outter = control_tx.clone();
    (
        tokio::spawn(async move {
            let mut packet_monitor: Option<PacketMonitor> = None;
            let mut web_handler: Option<WebServerHandler> = None;
            // controller channel for start/stop

            while let Some(msg) = control_rx.recv().await {
                let client = client.clone();
                match msg {
                    ControlMessage::Start => {
                        if packet_monitor.is_some() {
                            log::warn!("Already running, ignoring Start.");
                            continue;
                        }

                        match PacketMonitor::start(client.clone()).await {
                            Ok(pm_handler) => {
                                packet_monitor = Some(pm_handler);
                                if web_handler.is_none() {
                                    match WebServerBuilder::new(client)
                                        .bind_addr(BIND_ADDR)
                                        .cert_paths(TLS_CERT, TLS_KEY)
                                        .add_control(control_tx.clone())
                                        .spawn()
                                        .await
                                    {
                                        Ok(ws_handler) => {
                                            web_handler = Some(ws_handler);
                                        }
                                        Err(e) => {
                                            log::error!("Failed to start webserver: {e}");
                                            signal_handle.notify_one();
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Failed to start packet monitor: {e}");
                                signal_handle.notify_one();
                                break;
                            }
                        }
                    }
                    ControlMessage::Stop => {
                        if let Some(pm) = packet_monitor.take() {
                            pm.stop();
                            let _ = pm.handle.await;
                        }
                        log::info!("Stopped PacketMonitor");
                    }
                    ControlMessage::GetStatus(reply_tx) => {
                        let running = packet_monitor.is_some() && web_handler.is_some();
                        let _ = reply_tx.send(running);
                    }
                    ControlMessage::Quit => {
                        if let Some(pm) = packet_monitor.take() {
                            pm.stop();
                            let _ = pm.handle.await;
                        }
                        if let Some(ws) = web_handler.take() {
                            ws.stop();
                            let _ = ws.handle.await;
                        }
                        break;
                    }
                }
            }
        }),
        control_tx_outter,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    let _log = LogStart::start();
    let client = IPCClient::connect().await?;
    // Trigger via process or triggered outside by the OS to stop the process properly.
    let manual_trigger = Arc::new(Notify::new());

    wait_for_remote_object(&client).await?;

    let (cntrl_handle, cancel) = control_manager(client, Arc::clone(&manual_trigger)).await;

    let _ = cancel.send(ControlMessage::Start).await;
    // wait here until signal is sent
    signal::wait_until_signal(manual_trigger).await;
    let _ = cancel.send(ControlMessage::Quit).await;
    let _ = cntrl_handle.await;
    Ok(())
}
