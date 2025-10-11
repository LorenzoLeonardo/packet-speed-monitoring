use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ipc_broker::client::ClientHandle;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::task::JoinHandle;

use crate::speed_info::SpeedInfo;

#[derive(Serialize, Deserialize, Debug)]
pub struct BroadcastData {
    current: SpeedInfo,
    max: SpeedInfo,
}

impl BroadcastData {
    pub fn new(current: SpeedInfo, max: SpeedInfo) -> Self {
        Self { current, max }
    }
}

pub async fn publish_speed_info(
    mut broadcaster_rx: UnboundedReceiver<Vec<BroadcastData>>,
    shutdown: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, std::io::Error> {
    let client = ClientHandle::connect().await?;

    Ok(tokio::spawn(async move {
        loop {
            if shutdown.load(Ordering::Relaxed) {
                log::info!("[publisher] shutdown requested: exiting publisher loop");
                break;
            }
            match broadcaster_rx.recv().await {
                Some(val) => {
                    log::debug!("signal received: {val:?}");
                    if let Ok(value) = serde_json::to_value(&val) {
                        let _ = client
                            .publish("application.lan.speed", "speedInfo", &value)
                            .await;
                    } else {
                        log::error!("[publisher] parse error to Value.");
                        break;
                    }
                }
                None => {
                    log::info!("[publisher] rx channel closed, exiting...");
                    break;
                }
            }
        }
        log::info!("[publisher] publisher thread exiting cleanly")
    }))
}
