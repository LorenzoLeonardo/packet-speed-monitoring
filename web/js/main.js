import { setupTimezones } from "./timezone.js";
import { setupControls } from "./controls.js";
import { initSSE } from "./sse.js";
import { initDeviceDropdown } from "./devices.js";
import { rerenderAllRows } from "./render.js";

document.addEventListener("DOMContentLoaded", () => {
    const deviceSelect = document.getElementById("device-select");

    setupTimezones(rerenderAllRows);
    setupControls();
    initDeviceDropdown(deviceSelect);
    initSSE();
});
