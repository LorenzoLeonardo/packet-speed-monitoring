export async function toggleButtons(running) {
    const startBtn = document.getElementById("start-btn");
    const stopBtn = document.getElementById("stop-btn");
    startBtn.style.display = running ? "none" : "inline-block";
    stopBtn.style.display = running ? "inline-block" : "none";
}

export async function checkStatus() {
    try {
        const res = await fetch("/status");
        const data = await res.json();
        toggleButtons(data.running);
    } catch (err) {
        console.error("Failed to get status", err);
    }
}

export function setupControls() {
    const startBtn = document.getElementById("start-btn");
    const stopBtn = document.getElementById("stop-btn");
    const msInput = document.getElementById("ms-input");

    // Attach button events
    startBtn.addEventListener("click", startListener);
    stopBtn.addEventListener("click", stopListener);

    msInput.addEventListener("input", () => {
        let value = parseInt(msInput.value, 10);

        // Clamp the value within min and max range
        if (isNaN(value) || value < 100) {
            value = 100;
        } else if (value > 5000) {
            value = 5000;
        }

        msInput.value = value;

        // Enable start button since input is always valid now
        startBtn.disabled = false;
    });

    // Initialize button enabled
    startBtn.disabled = false;
}

export async function startListener() {
    await fetch("/start", { method: "POST" });
    toggleButtons(true);
}

export async function stopListener() {
    await fetch("/stop", { method: "POST" });
    toggleButtons(false);
}
