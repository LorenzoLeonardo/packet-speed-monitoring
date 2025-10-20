use std::sync::Arc;

use anyhow::Result;
use ipc_broker::client::IPCClient;
use tokio::{
    sync::{
        Notify,
        mpsc::{self, Sender},
        oneshot,
    },
    task::JoinHandle,
};

use crate::{BIND_ADDR, TLS_CERT, TLS_KEY, monitor::PacketMonitor, webserver::WebServerBuilder};

#[derive(Debug)]
pub enum ControlMessage {
    Start,
    Stop,
    GetStatus(oneshot::Sender<bool>),
    Quit,
}

pub struct ControlHandler {
    handle: JoinHandle<()>,
    tx: Sender<ControlMessage>,
}

impl ControlHandler {
    pub async fn start(&self) {
        if let Err(e) = self.tx.send(ControlMessage::Start).await {
            log::error!("{e}");
        }
    }
    pub async fn stop(self) {
        if let Err(e) = self.tx.send(ControlMessage::Quit).await {
            log::error!("{e}");
        }
        if let Err(e) = self.handle.await {
            log::error!("{e}");
        }
    }
}

pub struct SystemManager {
    client: IPCClient,
    signal_handle: Arc<Notify>,
}

impl SystemManager {
    pub fn new(client: IPCClient, signal_handle: Arc<Notify>) -> Self {
        Self {
            client,
            signal_handle,
        }
    }

    pub async fn spawn(&self) -> Result<ControlHandler> {
        let (control_tx, mut control_rx) = mpsc::channel::<ControlMessage>(8);
        // --- Spawn control background task ---
        let client = self.client.clone();
        let signal_handle = self.signal_handle.clone();
        let control_tx_outter = control_tx.clone();

        let web_handler = WebServerBuilder::new(client.clone())
            .bind_addr(BIND_ADDR)
            .cert_paths(TLS_CERT, TLS_KEY)
            .add_control(control_tx.clone())
            .spawn()
            .await?;

        let cntrl_fut = async move {
            let mut packet_monitor: Option<PacketMonitor> = None;
            log::info!("[manager] SystemManager has started.");
            while let Some(msg) = control_rx.recv().await {
                let client = client.clone();
                match msg {
                    ControlMessage::Start => {
                        if packet_monitor.is_some() {
                            log::warn!("[manager] Already running, ignoring Start.");
                            continue;
                        }

                        match PacketMonitor::start(client.clone()).await {
                            Ok(pm_handler) => {
                                packet_monitor = Some(pm_handler);
                                log::info!("[manager] Started PacketMonitor");
                            }
                            Err(e) => {
                                log::error!("[manager] Failed to start packet monitor: {e}");
                                signal_handle.notify_one();
                            }
                        }
                    }
                    ControlMessage::Stop => {
                        if let Some(pm) = packet_monitor.take() {
                            pm.stop();
                            let _ = pm.handle.await;
                            log::info!("[manager] Stopped PacketMonitor");
                        }
                    }
                    ControlMessage::GetStatus(reply_tx) => {
                        let running = packet_monitor.is_some();
                        let _ = reply_tx.send(running);
                    }
                    ControlMessage::Quit => {
                        log::info!("[manager] SystemManager is exiting...");
                        if let Some(pm) = packet_monitor.take() {
                            pm.stop();
                            let _ = pm.handle.await;
                        }
                        web_handler.stop();
                        let _ = web_handler.handle.await;
                        break;
                    }
                }
            }
            log::info!("[manager] SystemManager has ended.");
        };
        Ok(ControlHandler {
            handle: tokio::spawn(cntrl_fut),
            tx: control_tx_outter,
        })
    }
}
