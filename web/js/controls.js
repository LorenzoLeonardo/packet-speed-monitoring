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

    // Attach to buttons
    startBtn.addEventListener("click", startListener);
    stopBtn.addEventListener("click", stopListener);
}

export async function startListener() {
    await fetch("/start", { method: "POST" });
    toggleButtons(true);
}

export async function stopListener() {
    await fetch("/stop", { method: "POST" });
    toggleButtons(false);
}
