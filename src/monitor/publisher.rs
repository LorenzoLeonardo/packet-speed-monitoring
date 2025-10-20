use anyhow::{Context, Result};
use ipc_broker::client::IPCClient;
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
    client: IPCClient,
    receiver: Option<UnboundedReceiver<Vec<BroadcastData>>>,
}

impl PublisherBuilder {
    /// Create a new publisher builder
    pub fn new(client: IPCClient) -> Self {
        Self {
            client,
            receiver: None,
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

    /// Start the async publisher task
    pub async fn spawn(self) -> Result<JoinHandle<()>> {
        let mut rx = self.receiver.context("Missing broadcaster receiver")?;
        let client = self.client.clone();

        Ok(tokio::spawn(async move {
            log::info!("[publisher] publisher task started.");
            loop {
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
                        log::info!("[publisher] channel closed, exiting...");
                        break;
                    }
                }
            }
            log::info!("[publisher] publisher task ended.");
        }))
    }
}
