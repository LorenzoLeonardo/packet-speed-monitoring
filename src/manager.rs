use std::sync::Arc;

use ipc_broker::client::IPCClient;
use tokio::{
    sync::{
        Notify,
        mpsc::{self, Sender},
        oneshot,
    },
    task::JoinHandle,
};

use crate::{
    BIND_ADDR, TLS_CERT, TLS_KEY,
    monitor::PacketMonitor,
    webserver::{WebServerBuilder, WebServerHandler},
};

#[derive(Debug)]
pub enum ControlMessage {
    Start,
    Stop,
    GetStatus(oneshot::Sender<bool>),
    Quit,
}

pub async fn control_manager(
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
