use anyhow::{Context, Result};
use async_pcap::AsyncCaptureHandle;
use ipc_broker::client::ClientHandle;
use tokio::{sync::mpsc::unbounded_channel, task::JoinHandle};

use crate::{device::DeviceInfo, listener::PacketListenerBuilder, publisher::PublisherBuilder};

pub struct PacketMonitor {
    async_capture_handle: AsyncCaptureHandle,
    pub handle: JoinHandle<()>,
}

impl PacketMonitor {
    pub async fn start(client: ClientHandle) -> Result<Self> {
        let (broadcaster_tx, broadcaster_rx) = unbounded_channel();
        let device = DeviceInfo::get_physical_device().context("No physical device found")?;
        // Spawn the packet listener and transmit the BroadcastData into the Publisher
        let (packet_listener_handle, async_capture_handle) = PacketListenerBuilder::new(device)
            .load_dns_resolver()?
            .transmitter_broadcast_data_channel(broadcaster_tx)
            .spawn()
            .await?;

        // Spawn the a publisher to receive the BroadcastData from the packet listener
        let publisher_handle = PublisherBuilder::new(client.clone())
            .receiver_broadcast_data_channel(broadcaster_rx)
            .spawn()
            .await?;

        let handle = tokio::spawn(async move {
            log::info!("[PacketMonitor] Monitoring has started.");
            let _ = tokio::join!(packet_listener_handle, publisher_handle);
            log::info!("[PacketMonitor] Monitoring has stopped.");
        });
        Ok(Self {
            async_capture_handle,
            handle,
        })
    }

    pub fn stop(&self) {
        self.async_capture_handle.stop();
    }
}
