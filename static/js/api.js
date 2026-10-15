/**
 * IntentLock - Frontend API and UI Controller (Vanilla JavaScript)
 *
 * CRITICAL SECURITY RULES:
 * 1. Safe DOM updates: ALWAYS use `textContent` or `document.createElement`, NEVER `innerHTML`.
 * 2. Currency: Money is strictly formatted from integer cents, avoiding float arithmetic drift.
 * 3. Privacy: Never print or display a full token or private key (masked preview only).
 * 4. Honesty: Transparently display prototype limits and mock store parameters.
 */

// Format integer cents into a standard currency string ($XX.XX)
// Security note: We use integer math to prevent floating point imprecision.
function formatCents(cents) {
    if (typeof cents !== "number" || isNaN(cents)) {
        return "$0.00";
    }
    const dollars = Math.floor(cents / 100);
    const remainder = Math.abs(cents % 100);
    return `$${dollars}.${remainder.toString().padStart(2, "0")}`;
}

// Mask cryptographic tokens for safe UI display (e.g., 'eyJhbGci...a8f9')
// RULE: Never display full private keys or authorization tokens on screen.
function maskToken(token) {
    if (!token || typeof token !== "string") return "—";
    if (token.length <= 16) return "...";
    return `${token.substring(0, 10)}...${token.substring(token.length - 6)}`;
}

// Format Unix timestamp (seconds) into human-readable local time
function formatTimestamp(ts) {
    if (!ts) return "—";
    const date = new Date(ts * 1000);
    return date.toLocaleString();
}

// Helper: Safely create an element with specified classes and text content
function createEl(tag, text = "", classNames = []) {
    const el = document.createElement(tag);
    if (text) {
        // XSS Prevention: textContent guarantees untrusted data is treated purely as plain text
        el.textContent = text;
    }
    if (Array.isArray(classNames)) {
        classNames.forEach((cls) => el.classList.add(cls));
    } else if (typeof classNames === "string") {
        el.className = classNames;
    }
    return el;
}

// Toast notification helper for action feedback
function showToast(message, type = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
        container = createEl("div", "", "toast-container");
        container.id = "toast-container";
        document.body.appendChild(container);
    }

    const toast = createEl("div", message, ["toast", `toast-${type}`]);
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// API Service Client
const IntentLockAPI = {
    // Check backend health
    async getHealth() {
        const res = await fetch("/health");
        if (!res.ok) throw new Error(`Health check failed: ${res.status}`);
        return res.json();
    },

    // Fetch public key PEM
    async getPublicKey() {
        const res = await fetch("/api/public-key");
        if (!res.ok) throw new Error(`Failed to fetch public key: ${res.status}`);
        return res.text();
    },

    // List intents by status (pending, approved, rejected, or all)
    async listIntents(status = null) {
        const url = status ? `/api/intents?status=${encodeURIComponent(status)}` : "/api/intents";
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Failed to list intents: ${res.status}`);
        return res.json();
    },

    // Propose a new intent
    async createIntent(payload) {
        const res = await fetch("/api/intents", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Failed to create intent (${res.status})`);
        }
        return res.json();
    },

    // Human approves pending intent -> receives single-use Ed25519 token
    async approveIntent(intentId) {
        const res = await fetch(`/api/intents/${encodeURIComponent(intentId)}/approve`, {
            method: "POST",
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Approval failed (${res.status})`);
        }
        return res.json();
    },

    // Human rejects pending intent
    async rejectIntent(intentId) {
        const res = await fetch(`/api/intents/${encodeURIComponent(intentId)}/reject`, {
            method: "POST",
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Rejection failed (${res.status})`);
        }
        return res.json();
    },

    // Fetch store catalog
    async getStoreCatalog() {
        const res = await fetch("/store/catalog");
        if (!res.ok) throw new Error(`Failed to load catalog: ${res.status}`);
        return res.json();
    },

    // Fetch completed store orders
    async getStoreOrders() {
        const res = await fetch("/store/orders");
        if (!res.ok) throw new Error(`Failed to load orders: ${res.status}`);
        return res.json();
    },

    // Fetch attack scenarios
    async getScenarios() {
        const res = await fetch("/api/demo/scenarios");
        if (!res.ok) throw new Error(`Failed to load scenarios: ${res.status}`);
        return res.json();
    },

    // Run simulated agent scenario
    async runScenario(scenarioId, protectedMode, autoApprove = true) {
        const res = await fetch("/api/demo/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                scenario_id: scenarioId,
                protected: protectedMode,
                auto_approve: autoApprove,
            }),
        });
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Simulation run failed (${res.status})`);
        }
        return res.json();
    },
};

// Global system status updater
async function initSystemStatus() {
    const statusText = document.getElementById("system-status-text");
    const pubKeyText = document.getElementById("public-key-badge");

    try {
        const health = await IntentLockAPI.getHealth();
        if (statusText) {
            statusText.textContent = `Server Status: ${health.status.toUpperCase()} (Online)`;
        }

        if (pubKeyText) {
            const pem = await IntentLockAPI.getPublicKey();
            const lines = pem.trim().split("\n");
            // Show fingerprint/first body line
            const snippet = lines.length > 2 ? lines[1].substring(0, 16) : "Active";
            pubKeyText.textContent = `Ed25519 Issuer: ${snippet}...`;
        }
    } catch (err) {
        if (statusText) {
            statusText.textContent = "Server Offline (Cannot connect)";
            statusText.style.color = "var(--danger)";
        }
    }
}

// Export helpers to global scope
window.formatCents = formatCents;
window.maskToken = maskToken;
window.formatTimestamp = formatTimestamp;
window.createEl = createEl;
window.showToast = showToast;
window.IntentLockAPI = IntentLockAPI;
window.initSystemStatus = initSystemStatus;
