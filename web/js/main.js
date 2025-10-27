import { setupTimezones } from './timezone.js';
import { setupControls, toggleButtons, checkStatus, stopListener } from './controls.js';
import { renderRow, rerenderAllRows, sortTable, rowDataMap } from './render.js';

// Initialize SSE
const evtSource = new EventSource("/events");

const deviceSelect = document.getElementById("device-select");
let deviceList = [];

setupTimezones(rerenderAllRows);
setupControls();

evtSource.onmessage = (event) => {
    try {
        const msg = JSON.parse(event.data);
        if (msg.type === "init") {
            toggleButtons(msg.status.running);
            deviceList = msg.devices || [];
            const selectedDevice = msg.selected || null;
            populateDropdown(deviceList, selectedDevice);
            updateSelectedDevice(selectedDevice);
            return;
        }

        if (msg.type === "selected") {
            const dev = data.selected;
            if (!dev) return;

            updateSelectedDevice(dev);
        }

        if (msg.type === "status") {
            toggleButtons(msg.running);
            const tableBody = document.querySelector("#speed-table tbody");
            tableBody.innerHTML = ""; // clears all rows
            return;
        }

        if (!Array.isArray(msg)) {
            console.warn("Unexpected data format:", msg);
            return;
        }

        for (const data of msg) {
            const { current, max } = data;
            const ip = current.ip;
            rowDataMap.set(ip, data);
            renderRow(ip, current, max);
        }

        sortTable();
    } catch (err) {
        console.error("Bad JSON", event.data, err);
    }
};

checkStatus();

// Fill dropdown with devices
function populateDropdown(devices, selectedDevice = null) {
    deviceSelect.innerHTML = "";

    const defaultOpt = document.createElement("option");
    defaultOpt.value = "";
    defaultOpt.textContent = "-- Select a device --";
    deviceSelect.appendChild(defaultOpt);

    devices.forEach((dev, i) => {
        const opt = document.createElement("option");
        opt.value = i;
        opt.textContent = dev.desc && dev.desc.trim() !== ""
            ? dev.desc
            : dev.name;

        // Auto-select by matching device_ip
        if (selectedDevice && dev.device_ip === selectedDevice.device_ip) {
            opt.selected = true;
        }

        deviceSelect.appendChild(opt);
    });
}

deviceSelect.addEventListener("change", async (e) => {

    const idx = e.target.value;
    if (idx === "") {
        // 🧹 Clear device info when "Select a device" is chosen
        document.getElementById("device-desc").textContent = "—";
        document.getElementById("device-ip").textContent = "—";
        document.getElementById("network-ip").textContent = "—";
        document.getElementById("subnet-mask").textContent = "—";

        // Optionally stop monitoring here too
        try {
            stopListener();
        } catch (err) {
            console.warn("Failed to stop monitoring:", err);
        }
        return;
    }

    const dev = deviceList[idx];
    try {
        stopListener();
        updateSelectedDevice(dev);
        // 1️⃣ Send selected device to backend
        await fetch("/select", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(dev),
        });
    } catch (err) {
        console.error("Failed to start monitor:", err);
        alert("Failed to start monitoring. Check console for details.");
    }
});

function updateSelectedDevice(dev) {
    const idx = deviceList.findIndex(d => d.device_ip === dev.device_ip);
    if (idx === -1) return;
    deviceSelect.value = idx;

    //document.getElementById("device-name").textContent = dev.name;
    document.getElementById("device-desc").textContent = dev.desc;
    document.getElementById("device-ip").textContent = dev.device_ip;
    document.getElementById("network-ip").textContent = dev.network_ip;
    document.getElementById("subnet-mask").textContent = dev.netmask;

    const tableBody = document.querySelector("#speed-table tbody");
    tableBody.innerHTML = ""; // clears all rows
}
