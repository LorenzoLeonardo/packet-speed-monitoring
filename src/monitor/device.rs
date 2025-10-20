use std::net::{IpAddr, Ipv4Addr};

use anyhow::{Context, Result};
use async_pcap::{ConnectionStatus, Device};
use serde::Serialize;

use crate::helpers;

#[derive(Serialize, Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub desc: String,
    pub device_ip: Ipv4Addr,
    pub network_ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

impl TryFrom<&DeviceInfo> for Device {
    type Error = anyhow::Error;

    fn try_from(value: &DeviceInfo) -> Result<Self, Self::Error> {
        let devices = Device::list().map_err(|err| anyhow::anyhow!(err))?;

        devices
            .iter()
            .find(|dev| dev.name == value.name)
            .cloned()
            .context("Device not found")
    }
}

impl TryFrom<&Device> for DeviceInfo {
    type Error = anyhow::Error;

    fn try_from(device: &Device) -> Result<Self, Self::Error> {
        for address in device.addresses.iter() {
            if address.addr.is_ipv4()
                && let IpAddr::V4(device_ip) = address.addr
                && let IpAddr::V4(netmask) = address.netmask.context("Subnet mask not found")?
            {
                let network_ip = helpers::network_address(device_ip, netmask);
                return Ok(Self {
                    name: device.name.clone(),
                    desc: device.desc.clone().unwrap_or_default(),
                    device_ip,
                    network_ip,
                    netmask,
                });
            }
        }
        Err(anyhow::anyhow!(
            "No valid IPv4 subnet found on device {}",
            device.name
        ))
    }
}

impl DeviceInfo {
    pub fn get_physical_device() -> Option<DeviceInfo> {
        let physical = Self::find_connected_devices()
            .iter()
            .find(|dev| {
                let octets = dev.device_ip.octets();
                let is_physical_private =
                    (octets[0] == 10) || (octets[0] == 192 && octets[1] == 168);

                is_physical_private
                    && !dev.device_ip.is_loopback()
                    && !dev.device_ip.is_multicast()
                    && !dev.device_ip.is_unspecified()
            })
            .cloned()?;
        log::info!("Detected physical interface:");
        log::info!("    ↳ Name: {:?}", physical.name);
        log::info!("    ↳ Description: {:?}", physical.desc);
        log::info!("    ↳ Device Address: {}", physical.device_ip);
        log::info!("    ↳ Network Address: {}", physical.network_ip);
        log::info!("    ↳ Subnet Mask: {}", physical.netmask);
        Some(physical)
    }
    pub fn find_connected_devices() -> Vec<DeviceInfo> {
        // Get the list of devices, return an empty Vec if listing fails
        let devices = match Device::list() {
            Ok(devs) => devs,
            Err(_) => return Vec::new(),
        };

        // Filter all devices that meet the given conditions
        let filtered: Vec<DeviceInfo> = devices
            .into_iter()
            .filter(|d| {
                d.flags.connection_status == ConnectionStatus::Connected
                    && d.addresses.iter().any(|item| {
                        if let IpAddr::V4(ipv4) = item.addr {
                            item.netmask.is_some()
                                && item.broadcast_addr.is_some()
                                && !ipv4.is_loopback()
                                && !ipv4.is_multicast()
                                && !ipv4.is_unspecified()
                        } else {
                            false
                        }
                    })
            })
            .filter_map(|device| match DeviceInfo::try_from(&device) {
                Ok(info) => Some(info),
                Err(err) => {
                    log::warn!("Skipping device due to error: {err}");
                    None
                }
            })
            .collect();
        log::info!("Filtered connected devices: {:#?}", filtered);
        filtered
    }
}
