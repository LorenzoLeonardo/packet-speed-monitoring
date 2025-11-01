// Global shared state for your web app
export let selectedDeviceIp = null;

export function setSelectedDeviceIp(ip) {
    selectedDeviceIp = ip;
    // Optional: persist it in localStorage for reload persistence
    localStorage.setItem("selectedDeviceIp", ip);
}

export function getSelectedDeviceIp() {
    // Try getting the latest from memory or fallback to localStorage
    return selectedDeviceIp || localStorage.getItem("selectedDeviceIp");
}