use std::collections::hash_map::Entry;
use std::{collections::HashMap, net::Ipv4Addr};

use chrono::{Local, Offset, Utc};
use serde::{Deserialize, Serialize};

use crate::helpers::{ip_in_subnet, is_reserved_ip};

#[derive(Default)]
pub struct Stats {
    upload_bytes: usize,
    download_bytes: usize,
}

impl Stats {
    pub fn upload_bytes(&self) -> usize {
        self.upload_bytes
    }

    pub fn download_bytes(&self) -> usize {
        self.download_bytes
    }

    pub fn reset(&mut self) {
        self.upload_bytes = 0;
        self.download_bytes = 0;
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SpeedInfo {
    ip: String,
    hostname: String,
    mac: String,
    mbps_down: f64,
    mbps_up: f64,
    time_utc: String,
    timezone: String,
    time_utc_down: Option<String>,
    time_utc_up: Option<String>,
}

impl SpeedInfo {
    pub fn new(ip: String, hostname: String, down: f64, up: f64, mac: String) -> Self {
        let timestamp = Utc::now();
        let local_time = Local::now();

        // Compute offset between local time and UTC
        let offset_seconds = local_time.offset().fix().local_minus_utc();
        let hours = offset_seconds / 3600;
        let minutes = (offset_seconds.abs() % 3600) / 60;

        let sign = if offset_seconds >= 0 { '+' } else { '-' };
        let timezone = format!("UTC{}{:02}:{:02}", sign, hours.abs(), minutes);

        Self {
            ip,
            hostname,
            mac,
            mbps_down: down,
            mbps_up: up,
            time_utc: timestamp.to_rfc3339(),
            timezone,
            time_utc_down: None,
            time_utc_up: None,
        }
    }
}

/// Update in-memory max speeds (per IP)
pub fn update_max_speed_local(map: &mut HashMap<Ipv4Addr, SpeedInfo>, data: &SpeedInfo) {
    // If IP fails to parse, skip the update (avoid inserting 0.0.0.0 entries)
    let ip: Ipv4Addr = match data.ip.parse() {
        Ok(ip) => ip,
        Err(_) => return,
    };

    match map.entry(ip) {
        Entry::Occupied(mut e) => {
            let max = e.get_mut();
            let mut changed = false;
            let now = Utc::now();
            // Update download max independently
            if data.mbps_down > max.mbps_down {
                max.mbps_down = data.mbps_down;
                max.time_utc_down = Some(now.to_string());
                max.timezone = data.timezone.clone();
                changed = true;
            }

            // Update upload max independently
            if data.mbps_up > max.mbps_up {
                max.mbps_up = data.mbps_up;
                max.time_utc_up = Some(now.to_string());
                max.timezone = data.timezone.clone();
                changed = true;
            }

            if changed {
                log::debug!(
                    "Updated max for {} => down: {:.6}, up: {:.6}",
                    data.ip,
                    max.mbps_down,
                    max.mbps_up
                );
            }
        }
        Entry::Vacant(e) => {
            let mut entry = data.clone();
            let now = Utc::now().to_rfc3339();
            entry.time_utc_down = Some(now.clone());
            entry.time_utc_up = Some(now);
            e.insert(entry);
        }
    }
}

/// Update upload/download statistics
pub fn update_stats(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    size: usize,
    stats: &mut HashMap<Ipv4Addr, Stats>,
    subnet: &Ipv4Addr,
    mask: &Ipv4Addr,
) {
    if ip_in_subnet(src, *subnet, *mask) && !is_reserved_ip(src, *subnet, *mask) {
        stats.entry(src).or_default().upload_bytes += size;
    }
    if ip_in_subnet(dst, *subnet, *mask) && !is_reserved_ip(dst, *subnet, *mask) {
        stats.entry(dst).or_default().download_bytes += size;
    }
}
