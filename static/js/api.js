// IntentLock Frontend API Helper
// RULE: Always use textContent when updating DOM with server data (never innerHTML)

document.addEventListener("DOMContentLoaded", () => {
    const statusEl = document.getElementById("system-status");
    if (!statusEl) return;

    fetch("/health")
        .then((res) => res.json())
        .then((data) => {
            // Safe assignment using textContent to prevent XSS
            statusEl.textContent = `Server Status: ${data.status}`;
        })
        .catch((err) => {
            statusEl.textContent = "Error connecting to server";
        });
});
