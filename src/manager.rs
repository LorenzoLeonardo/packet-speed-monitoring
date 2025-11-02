use std::sync::Arc;

use anyhow::Result;
use ipc_broker::client::IPCClient;
use tokio::{
    sync::{
        Notify, broadcast,
        mpsc::{self, Sender},
        oneshot,
    },
    task::JoinHandle,
};

use crate::{
    BIND_ADDR, TLS_CERT, TLS_KEY,
    monitor::{PacketMonitor, device::DeviceInfo},
    webserver::WebServerBuilder,
};

#[derive(Debug)]
pub enum ControlMessage {
    Start,
    Stop,
    GetStatus(oneshot::Sender<bool>),
    GetDeviceInfo(oneshot::Sender<Vec<DeviceInfo>>),
    SelectDevice(DeviceInfo),
    GetSelectedDevice(oneshot::Sender<Option<DeviceInfo>>),
    GiveLogSSEHandle(JoinHandle<()>),
    GiveWebSSEHandle(JoinHandle<()>),
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
    sse_log_tx: broadcast::Sender<String>,
}

impl SystemManager {
    pub fn new(
        client: IPCClient,
        signal_handle: Arc<Notify>,
        sse_log_tx: broadcast::Sender<String>,
    ) -> Self {
        Self {
            client,
            signal_handle,
            sse_log_tx,
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
            .add_sender_channel(control_tx.clone())
            .add_log_channel(self.sse_log_tx.clone())
            .spawn()
            .await?;

        let cntrl_fut = async move {
            let available_devices: Vec<DeviceInfo> = DeviceInfo::find_connected_devices();
            let mut packet_monitor: Option<PacketMonitor> = None;
            let mut selected_device: Option<DeviceInfo> = None;
            let mut sse_log_handle: Option<JoinHandle<()>> = None;
            let mut sse_web_handle: Option<JoinHandle<()>> = None;
            log::info!("[manager] SystemManager has started.");
            while let Some(msg) = control_rx.recv().await {
                let client = client.clone();
                match msg {
                    ControlMessage::Start => {
                        if packet_monitor.is_some() {
                            log::warn!("[manager] Already running, ignoring Start.");
                            continue;
                        }
                        if let Some(device) = &selected_device {
                            match PacketMonitor::start(client.clone(), device.clone()).await {
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
                    ControlMessage::GetDeviceInfo(reply_tx) => {
                        let _ = reply_tx.send(available_devices.clone());
                    }
                    ControlMessage::SelectDevice(device_info) => {
                        // Set selected device
                        selected_device = Some(device_info.clone());
                        log::info!("[manager] Selected device: {selected_device:?}");
                    }
                    ControlMessage::GetSelectedDevice(reply_tx) => {
                        let _ = reply_tx.send(selected_device.clone());
                    }
                    ControlMessage::GiveLogSSEHandle(handle) => {
                        sse_log_handle = Some(handle);
                    }
                    ControlMessage::GiveWebSSEHandle(handle) => {
                        sse_web_handle = Some(handle);
                    }
                    ControlMessage::Quit => {
                        log::info!("[manager] SystemManager is exiting...");
                        if let Some(pm) = packet_monitor.take() {
                            pm.stop();
                            let _ = pm.handle.await;
                        }

                        web_handler.stop();

                        if let Some(sse_web_handle) = sse_web_handle.take() {
                            let _ = tokio::join!(web_handler.handle, sse_web_handle);
                        } else {
                            let _ = web_handler.handle.await;
                        }
                        break;
                    }
                }
            }
            log::info!("[manager] SystemManager has ended.");

            if let Some(see_log_handle) = sse_log_handle.take() {
                let _ = see_log_handle.await;
            }
        };
        Ok(ControlHandler {
            handle: tokio::spawn(cntrl_fut),
            tx: control_tx_outter,
        })
    }
}
