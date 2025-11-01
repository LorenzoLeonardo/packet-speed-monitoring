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

export function updateSelectedDevice(dev) {
    const idx = deviceList.findIndex(d => d.device_ip === dev.device_ip);
    if (idx === -1) return;
    deviceSelect.value = idx;

    document.getElementById("device-desc").textContent = dev.desc || "—";
    document.getElementById("device-ip").textContent = dev.device_ip || "—";
    document.getElementById("network-ip").textContent = dev.network_ip || "—";
    document.getElementById("subnet-mask").textContent = dev.netmask || "—";

    document.querySelector("#speed-table tbody").innerHTML = "";

    setSelectedDeviceIp(dev.device_ip);
}

function clearDeviceInfo() {
    ["device-desc", "device-ip", "network-ip", "subnet-mask"].forEach(id => {
        document.getElementById(id).textContent = "—";
    });
}
