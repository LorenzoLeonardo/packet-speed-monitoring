# 🖥️ Packet Speed Monitor

**Packet Speed Monitor** is a lightweight Rust application that monitors the **upload and download speeds of all computers connected to your local subnet**.  
It captures real-time packet data, calculates per-IP bandwidth usage, and serves live statistics through a built-in web interface or publishes them via an IPC broker.

---

## 🎯 Purpose

The goal of this project is to **track and display network speed usage (upload/download)** for every computer connected within the same LAN subnet.  
This is especially useful for:
- Home networks to identify high-bandwidth users  
- Small office LANs to monitor overall network health  
- Embedded systems or routers needing bandwidth visibility  

---

## 🚀 Features

- 🧠 **Subnet-Wide Monitoring**  
  Automatically detects your active network interface and monitors every device within your local subnet.
  
- ⚡ **Real-Time Throughput Calculation**  
  Measures Mbps (upload/download) per IP in real time using packet-level inspection.

- 🧩 **Auto Interface Detection**  
  Detects active wired/wireless interfaces and filters out virtual, VPN, or loopback devices.

- 🌐 **Built-In Web Dashboard**  
  Displays live LAN traffic statistics in your browser.

- 🔗 **IPC Broker Integration**  
  Publishes real-time speed information to an inter-process communication system for integration with other services.

- 🕓 **Timezone-Aware Data**  
  Each record includes both UTC and local timestamps with proper timezone offset.

---

## 🧰 Requirements

| Component | Requirement |
|------------|--------------|
| **Rust** | v1.75+ |
| **Npcap / libpcap** | Required for packet capture |
| **Privileges** | Administrator / Root access for packet sniffing |

Installation of pcap:
```bash
# Linux
sudo apt install libpcap-dev

# macOS
# Already included by default

# Windows
Download and install Npcap from:
https://npcap.com/dist/npcap-sdk-1.13.zip
```

## ▶️ Running the Program

Run with admin/root privileges:
```bash
sudo ./target/release/packet-speed-monitor
```

## ⚡ Architecture Overview

```
┌────────────────────┐
│  Packet Sniffer    │
│ (pcap + etherparse)│
└───────┬────────────┘
        │
        ▼
┌────────────────────┐
│ Speed Calculator   │
│ (upload/download)  │
└───────┬────────────┘
        │
        ▼
┌────────────────────┐
│ IPC Publisher      │
│ (ipc_broker)       │
└───────┬────────────┘
        │
        ▼
┌────────────────────┐
│ Web Dashboard      │
│ (Axum Web Server)  │
└────────────────────┘
```

---

## 🧱 Use Case Examples

- Monitor every device’s real-time bandwidth in a **home Wi-Fi network**  
- Deploy on a **LAN router or Raspberry Pi** for passive bandwidth tracking  
- Integrate with **dashboard systems** or **network alerts**
