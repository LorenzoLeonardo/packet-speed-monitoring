use std::net::Ipv4Addr;

use async_pcap::Device;
use pnet::{datalink, ipnetwork::IpNetwork};

/// Common keywords and exclusions used to identify real network interfaces
const KEYWORDS: [&str; 10] = [
    "wi-fi", "wireless", "ethernet", "lan", "eth", "enp", "eno", "en", "wlp", "wlan",
];
const EXCLUDED: [&str; 8] = [
    "loopback",
    "virtual",
    "vmware",
    "npcap",
    "hyper-v",
    "bluetooth",
    "tunnel",
    "vpn",
];

/// Returns true if the IP is reserved (broadcast, network, multicast, loopback, etc.)
/// or private but **outside** the given subnet.
pub(crate) fn is_reserved_ip(ip: Ipv4Addr, subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
    // Built-in checks first
    if ip.is_loopback() || ip.is_link_local() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }

    // Compute network and broadcast manually
    let ip_u32 = u32::from(ip);
    let mask_u32 = u32::from(mask);
    let net_u32 = u32::from(subnet) & mask_u32;
    let broadcast_u32 = net_u32 | !mask_u32;

    // Network or broadcast addresses within this subnet
    if ip_u32 == net_u32 || ip_u32 == broadcast_u32 {
        return true;
    }

    // Private IPs outside this subnet — e.g. 10.x.x.x or 172.16.x.x while your subnet is 192.168.x.x
    if ip.is_private() && (ip_u32 & mask_u32) != net_u32 {
        return true;
    }

    false
}

/// Check if an IP is in the given subnet
pub(crate) fn ip_in_subnet(ip: Ipv4Addr, subnet: Ipv4Addr, mask: Ipv4Addr) -> bool {
    (u32::from(ip) & u32::from(mask)) == (u32::from(subnet) & u32::from(mask))
}

/// Compute the network address from IP and mask
pub(crate) fn network_address(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(ip) & u32::from(mask))
}

/// Returns true if an interface/device name+desc matches known keywords
fn matches_keywords(name: &str, desc: &str) -> bool {
    let name = name.to_lowercase();
    let desc = desc.to_lowercase();
    KEYWORDS
        .iter()
        .any(|kw| name.contains(kw) || desc.contains(kw))
}

/// Returns true if an interface/device name+desc should be excluded
fn is_excluded(name: &str, desc: &str) -> bool {
    let name = name.to_lowercase();
    let desc = desc.to_lowercase();
    EXCLUDED
        .iter()
        .any(|ex| name.contains(ex) || desc.contains(ex))
}

/// Detect the active pcap device
pub fn find_active_device() -> Option<Device> {
    let devices = Device::list().ok()?;

    devices
        .iter()
        .find(|d| {
            let desc = d.desc.as_deref().unwrap_or("");
            !is_excluded(&d.name, desc) && matches_keywords(&d.name, desc)
        })
        .cloned()
        // fallback: any non-loopback device
        .or_else(|| {
            devices
                .iter()
                .find(|d| {
                    let desc = d.desc.as_deref().unwrap_or("");
                    !is_excluded(&d.name, desc) && !d.addresses.is_empty()
                })
                .cloned()
        })
}

/// Detect local IPv4 subnet from datalink interfaces
pub fn detect_local_subnet() -> Option<(Ipv4Addr, Ipv4Addr)> {
    let mut candidates = vec![];

    for iface in datalink::interfaces() {
        if is_excluded(&iface.name, &iface.description)
            || !matches_keywords(&iface.name, &iface.description)
        {
            continue;
        }

        for ip in iface.ips {
            if let IpNetwork::V4(net) = ip {
                log::info!("Detected interface: {}", iface.name);
                log::info!("   ↳ Description: {}", iface.description);
                log::info!("   ↳ Local IP: {}", net.ip());
                log::info!("   ↳ Subnet mask: {}", net.mask());
                candidates.push((iface.name.clone(), net.ip(), net.mask()));
            }
        }
    }

    // Prefer wired/wireless
    if let Some((name, ip, mask)) = candidates.iter().find(|(name, _, _)| {
        ["eth", "en", "wlp", "wlan"]
            .iter()
            .any(|kw| name.contains(kw))
    }) {
        log::info!("Selected primary interface: {name}");
        return Some((*ip, *mask));
    }

    // Fallback
    candidates.first().map(|(name, ip, mask)| {
        log::info!("Fallback interface: {name}");
        (*ip, *mask)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_network_and_broadcast_addresses() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        // Network address
        assert!(is_reserved_ip(Ipv4Addr::new(192, 168, 1, 0), subnet, mask));

        // Broadcast address
        assert!(is_reserved_ip(
            Ipv4Addr::new(192, 168, 1, 255),
            subnet,
            mask
        ));

        // Valid unicast address (not reserved)
        assert!(!is_reserved_ip(
            Ipv4Addr::new(192, 168, 1, 100),
            subnet,
            mask
        ));
    }

    #[test]
    fn test_loopback_linklocal_multicast_unspecified() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        // Loopback
        assert!(is_reserved_ip(Ipv4Addr::new(127, 0, 0, 1), subnet, mask));

        // Link-local (APIPA)
        assert!(is_reserved_ip(Ipv4Addr::new(169, 254, 10, 5), subnet, mask));

        // Multicast
        assert!(is_reserved_ip(Ipv4Addr::new(224, 0, 0, 1), subnet, mask));

        // Unspecified (0.0.0.0)
        assert!(is_reserved_ip(Ipv4Addr::new(0, 0, 0, 0), subnet, mask));
    }

    #[test]
    fn test_private_outside_subnet() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 0);

        // Private IP inside same subnet — should NOT be reserved
        assert!(!is_reserved_ip(
            Ipv4Addr::new(192, 168, 1, 42),
            subnet,
            mask
        ));

        // Private IP from another subnet — should be reserved
        assert!(is_reserved_ip(Ipv4Addr::new(10, 0, 0, 5), subnet, mask));
        assert!(is_reserved_ip(Ipv4Addr::new(172, 16, 0, 5), subnet, mask));

        // Public IP — not reserved
        assert!(!is_reserved_ip(Ipv4Addr::new(8, 8, 8, 8), subnet, mask));
    }

    #[test]
    fn test_small_subnet_edge_case() {
        let subnet = Ipv4Addr::new(192, 168, 1, 0);
        let mask = Ipv4Addr::new(255, 255, 255, 252); // /30 -> only 4 addresses (0–3)
        // network=192.168.1.0, broadcast=192.168.1.3, usable: 1 & 2

        assert!(is_reserved_ip(Ipv4Addr::new(192, 168, 1, 0), subnet, mask)); // network
        assert!(is_reserved_ip(Ipv4Addr::new(192, 168, 1, 3), subnet, mask)); // broadcast
        assert!(!is_reserved_ip(Ipv4Addr::new(192, 168, 1, 1), subnet, mask)); // valid
        assert!(!is_reserved_ip(Ipv4Addr::new(192, 168, 1, 2), subnet, mask)); // valid
    }
}
