export let currentTZ = Intl.DateTimeFormat().resolvedOptions().timeZone;
export const rowDataMap = new Map();

export function setupTimezones(onChange) {
    const tzSelect = document.getElementById("tz-select");
    const timeZones = Intl.supportedValuesOf("timeZone");

    for (const tz of timeZones) {
        const opt = document.createElement("option");
        opt.value = tz;
        opt.textContent = tz;
        if (tz === currentTZ) opt.selected = true;
        tzSelect.appendChild(opt);
    }

    tzSelect.addEventListener("change", () => {
        currentTZ = tzSelect.value;
        onChange();
    });
}
