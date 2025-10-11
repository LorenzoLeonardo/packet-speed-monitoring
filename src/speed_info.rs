use std::collections::hash_map::Entry;
use std::{collections::HashMap, net::Ipv4Addr};

use chrono::{FixedOffset, Local, Offset, Utc};
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
    mbps_down: f64,
    mbps_up: f64,
    time_local: String,
    time_utc: String,
    timezone: String,
}

impl SpeedInfo {
    pub fn new(ip: &str, hostname: &str, down: f64, up: f64) -> Self {
        let timestamp = Utc::now();
        let local_time = Local::now();

        // Compute offset between local time and UTC
        let offset_seconds = local_time.offset().fix().local_minus_utc();
        let hours = offset_seconds / 3600;
        let minutes = (offset_seconds.abs() % 3600) / 60;

        let sign = if offset_seconds >= 0 { '+' } else { '-' };
        let timezone = format!("UTC{}{:02}:{:02}", sign, hours.abs(), minutes);

        // Create FixedOffset and convert UTC → local
        let fixed_offset =
            FixedOffset::east_opt(offset_seconds).unwrap_or(FixedOffset::east_opt(0).unwrap());
        let local_time_str = timestamp.with_timezone(&fixed_offset).to_rfc3339();

        Self {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            mbps_down: down,
            mbps_up: up,
            time_local: local_time_str,
            time_utc: timestamp.to_rfc3339(),
            timezone,
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

            // Update download max independently
            if data.mbps_down > max.mbps_down {
                max.mbps_down = data.mbps_down;
                max.time_local = data.time_local.clone();
                max.time_utc = data.time_utc.clone();
                max.timezone = data.timezone.clone();
                changed = true;
            }

            // Update upload max independently
            if data.mbps_up > max.mbps_up {
                max.mbps_up = data.mbps_up;
                // Use the same timestamp fields to mark when upload max happened.
                // If you want separate timestamps for up/down, see note below.
                max.time_local = data.time_local.clone();
                max.time_utc = data.time_utc.clone();
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
            e.insert(data.clone());
            log::debug!(
                "Inserted new max record for {} => down: {:.6}, up: {:.6}",
                data.ip,
                data.mbps_down,
                data.mbps_up
            );
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
