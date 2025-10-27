import { toggleButtons, checkStatus } from "./controls.js";
import { renderRow, rerenderAllRows, sortTable, rowDataMap } from "./render.js";
import { populateDropdown, updateSelectedDevice, setDeviceList } from "./devices.js";

export function initSSE() {
    const evtSource = new EventSource("/events");

    evtSource.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);

            switch (msg.type) {
                case "init":
                    toggleButtons(msg.status.running);
                    setDeviceList(msg.devices || []);
                    populateDropdown(msg.selected);
                    updateSelectedDevice(msg.selected);
                    return;

                case "selected":
                    updateSelectedDevice(msg.selected);
                    return;

                case "status":
                    toggleButtons(msg.running);
                    document.querySelector("#speed-table tbody").innerHTML = "";
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
}
