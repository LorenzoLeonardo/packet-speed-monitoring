import { currentTZ } from './timezone.js';

export const rowDataMap = new Map();
const tbody = document.querySelector("#speed-table tbody");

function formatSpeed(mbps) {
    return mbps < 1 ? `${(mbps * 1000).toFixed(2)} Kbps` : `${mbps.toFixed(3)} Mbps`;
}

function formatDate(date) {
    if (!date) return "—";
    const opts = {
        year: "numeric", month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit", second: "2-digit",
        hour12: true, timeZone: currentTZ
    };
    return date.toLocaleString("en-US", opts);
}

export function renderRow(ip, curr, max) {
    const dateUTC = new Date(curr.time_utc);
    const dateMaxDownUTC = max.time_utc_down ? new Date(max.time_utc_down) : null;
    const dateMaxUpUTC = max.time_utc_up ? new Date(max.time_utc_up) : null;

    const rowHTML = `
    <td>${ip}</td>
    <td>${curr.hostname}</td>
    <td>${formatSpeed(curr.mbps_down)}</td>
    <td>${formatSpeed(curr.mbps_up)}</td>
    <td class="divider">${formatDate(dateUTC)}</td>
    <td class="hide-col after-timezone">${currentTZ}</td>
    <td>${formatSpeed(max.mbps_down)}</td>
    <td>${formatDate(dateMaxDownUTC)}</td>
    <td>${formatSpeed(max.mbps_up)}</td>
    <td>${formatDate(dateMaxUpUTC)}</td>
  `;

    const existingRow = document.querySelector(`tr[data-ip="${ip}"]`);
    if (existingRow) {
        existingRow.innerHTML = rowHTML;
    } else {
        const row = document.createElement("tr");
        row.dataset.ip = ip;
        row.innerHTML = rowHTML;
        tbody.appendChild(row);
    }
}

export function rerenderAllRows() {
    for (const [ip, data] of rowDataMap.entries()) {
        renderRow(ip, data.current, data.max);
    }
    sortTable();
}

export function sortTable() {
    const rows = Array.from(tbody.querySelectorAll("tr"));
    rows.sort((a, b) => a.dataset.ip.localeCompare(b.dataset.ip, undefined, { numeric: true }));
    rows.forEach(row => tbody.appendChild(row));
}
