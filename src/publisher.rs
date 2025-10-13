use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ipc_broker::client::ClientHandle;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;

use crate::speed_info::SpeedInfo;

/// Represents the data to broadcast to subscribers
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BroadcastData {
    current: SpeedInfo,
    max: SpeedInfo,
}

impl BroadcastData {
    pub fn new(current: SpeedInfo, max: SpeedInfo) -> Self {
        Self { current, max }
    }
}

/// Builder for configuring and running the publisher task
pub struct PublisherBuilder {
    receiver: Option<UnboundedReceiver<Vec<BroadcastData>>>,
    shutdown_flag: Option<Arc<AtomicBool>>,
    client: Option<ClientHandle>,
}

impl PublisherBuilder {
    /// Create a new publisher builder
    pub fn new() -> Self {
        Self {
            receiver: None,
            shutdown_flag: None,
            client: None,
        }
    }

    /// Attach an existing message receiver
    pub fn receiver_broadcast_data_channel(
        mut self,
        receiver: UnboundedReceiver<Vec<BroadcastData>>,
    ) -> Self {
        self.receiver = Some(receiver);
        self
    }

    /// Set the shutdown flag shared between tasks
    pub fn shutdown_flag(mut self, shutdown_flag: Arc<AtomicBool>) -> Self {
        self.shutdown_flag = Some(shutdown_flag);
        self
    }

    /// Connect automatically to the IPC broker if no client is provided
    pub async fn connect_client(mut self) -> Result<Self, std::io::Error> {
        let client = ClientHandle::connect().await?;
        self.client = Some(client);
        Ok(self)
    }

    /// Start the async publisher task
    pub async fn spawn(self) -> Result<JoinHandle<()>, std::io::Error> {
        let mut rx = self.receiver.expect("Missing broadcaster receiver");
        let shutdown = self.shutdown_flag.expect("Missing shutdown flag");
        let client = self.client.expect("Missing IPC client");

        Ok(tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    log::debug!("[publisher] shutdown requested: exiting publisher loop");
                    break;
                }

                match rx.recv().await {
                    Some(batch) => {
                        log::debug!("[publisher] received batch of {} entries", batch.len());
                        if let Ok(value) = serde_json::to_value(&batch) {
                            if let Err(e) = client
                                .publish("application.lan.speed", "speedInfo", &value)
                                .await
                            {
                                log::error!("[publisher] publish error: {e}");
                            }
                        } else {
                            log::error!("[publisher] failed to serialize broadcast data");
                            break;
                        }
                    }
                    None => {
                        log::debug!("[publisher] channel closed, exiting...");
                        break;
                    }
                }
            }
            log::info!("[publisher] publisher thread exited cleanly");
        }))
    }
}
