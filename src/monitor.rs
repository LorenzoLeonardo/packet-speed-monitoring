pub mod device;
mod hostname;
mod listener;
mod publisher;
mod speed_info;

use anyhow::Result;
use async_pcap::AsyncCaptureHandle;
use ipc_broker::client::IPCClient;
use tokio::{sync::mpsc::unbounded_channel, task::JoinHandle};

use crate::{
    monitor::device::DeviceInfo,
    monitor::{listener::PacketListenerBuilder, publisher::PublisherBuilder},
};

pub struct PacketMonitor {
    async_capture_handle: AsyncCaptureHandle,
    pub handle: JoinHandle<()>,
}

impl PacketMonitor {
    pub async fn start(client: IPCClient, device_info: DeviceInfo) -> Result<Self> {
        let (broadcaster_tx, broadcaster_rx) = unbounded_channel();
        // Spawn the packet listener and transmit the BroadcastData into the Publisher
        let (packet_listener_handle, async_capture_handle) =
            PacketListenerBuilder::new(device_info.clone())
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
