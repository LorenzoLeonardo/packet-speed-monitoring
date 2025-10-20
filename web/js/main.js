import { setupTimezones } from './timezone.js';
import { setupControls, toggleButtons, checkStatus } from './controls.js';
import { renderRow, rerenderAllRows, sortTable, rowDataMap } from './render.js';

// Initialize SSE
const evtSource = new EventSource("/events");

setupTimezones(rerenderAllRows);
setupControls();

evtSource.onmessage = (event) => {
    try {
        const msg = JSON.parse(event.data);

        if (msg.type === "status") {
            toggleButtons(msg.running);
            return;
        }

        if (msg.type === "device_info") {
            document.getElementById("device-name").textContent = msg.device_name;
            document.getElementById("device-desc").textContent = msg.description;
            document.getElementById("device-ip").textContent = msg.device_ip;
            document.getElementById("network-ip").textContent = msg.network_ip;
            document.getElementById("subnet-mask").textContent = msg.subnet_mask;
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
