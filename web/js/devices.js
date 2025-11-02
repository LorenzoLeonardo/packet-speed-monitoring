import { stopListener } from "./controls.js";
import { setSelectedDeviceIp } from "./state.js";

let deviceList = [];
let deviceSelect = null;

export function initDeviceDropdown(selectElement) {
    deviceSelect = selectElement;
    deviceSelect.addEventListener("change", handleDeviceChange);
}

export function setDeviceList(devices) {
    deviceList = devices;
}

export function populateDropdown(selectedDevice = null) {
    if (!deviceSelect) return;

    deviceSelect.innerHTML = "";

    const defaultOpt = document.createElement("option");
    defaultOpt.value = "";
    defaultOpt.textContent = "-- Select a device --";
    deviceSelect.appendChild(defaultOpt);

    deviceList.forEach((dev, i) => {
        const opt = document.createElement("option");
        opt.value = i;
        opt.textContent = dev.desc?.trim() || dev.name;

        if (selectedDevice && dev.device_ip === selectedDevice.device_ip) {
            opt.selected = true;
        }

        deviceSelect.appendChild(opt);
    });
}

async function handleDeviceChange(e) {
    const idx = e.target.value;
    if (idx === "") {
        clearDeviceInfo();
        try { stopListener(); } catch (err) {
            console.warn("Failed to stop monitoring:", err);
        }
        return;
    }

    const dev = deviceList[idx];
    try {
        stopListener();
        updateSelectedDevice(dev);
        await fetch("/select", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(dev),
        });
    } catch (err) {
        console.error("Failed to start monitor:", err);
        alert("Failed to start monitoring. Check console for details.");
    }
}

// Helper: convert IPv4 string to number
function ipToNumber(ip) {
    return ip.split('.').reduce((acc, oct) => (acc << 8) + parseInt(oct), 0);
}

// Helper: convert number to IPv4 string
function numberToIp(num) {
    return [
        (num >>> 24) & 0xFF,
        (num >>> 16) & 0xFF,
        (num >>> 8) & 0xFF,
        num & 0xFF
    ].join('.');
}

// Check if IP is reachable via HTTP
async function isReachable(ip) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1000); // 1s timeout

  try {
    const res = await fetch(`http://${ip}`, {
      mode: "no-cors", // prevents CORS blocking
      signal: controller.signal,
    });
    clearTimeout(timeout);
    // if no exception, assume reachable
    return true;
  } catch {
    clearTimeout(timeout);
    return false;
  }
}

export function updateSelectedDevice(dev) {
    const idx = deviceList.findIndex(d => d.device_ip === dev.device_ip);
    if (idx === -1) return;
    deviceSelect.value = idx;

    document.getElementById("device-desc").textContent = dev.desc || "—";
    document.getElementById("device-ip").textContent = dev.device_ip || "—";
    document.getElementById("network-ip").textContent = dev.network_ip || "—";
    document.getElementById("broadcast-ip").textContent = dev.broadcast_ip || "—";
    document.getElementById("subnet-mask").textContent = dev.netmask || "—";

    // Calculate router addresses if network_ip and broadcast_ip exist
    let routerStart = "—";
    let routerEnd = "—";

    if (dev.network_ip && dev.broadcast_ip) {
        try {
            const networkNum = ipToNumber(dev.network_ip);
            const broadcastNum = ipToNumber(dev.broadcast_ip);

            // Router addresses: first usable and last usable IP
            routerStart = numberToIp(networkNum + 1);
            routerEnd = numberToIp(broadcastNum - 1);
        } catch {
            // ignore errors, fallback to "—"
        }
    }

    const routerElem = document.getElementById("router-url");
    routerElem.textContent = "Checking…";

    // Test which router IP is reachable
    let reachableLink = "—";

    if (routerStart !== "—" && isReachable(routerStart)) {
        reachableLink = `<a href="http://${routerStart}" target="_blank" rel="noopener noreferrer">Go to router's page</a>`;
    } else if (routerEnd !== "—" && isReachable(routerEnd)) {
        reachableLink = `<a href="http://${routerEnd}" target="_blank" rel="noopener noreferrer">Go to router's page</a>`;
    }

  routerElem.innerHTML = reachableLink;

    document.querySelector("#speed-table tbody").innerHTML = "";

    setSelectedDeviceIp(dev.device_ip);
}

function clearDeviceInfo() {
    ["device-desc", "device-ip", "network-ip", "broadcast-ip", "subnet-mask", "router-url"].forEach(id => {
        document.getElementById(id).textContent = "—";
    });
}
