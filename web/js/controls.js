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

    startBtn.addEventListener("click", async () => {
        await fetch("/start", { method: "POST" });
        toggleButtons(true);
    });

    stopBtn.addEventListener("click", async () => {
        await fetch("/stop", { method: "POST" });
        toggleButtons(false);
    });
}
