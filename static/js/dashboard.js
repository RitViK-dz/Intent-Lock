/**
 * IntentLock - Live Human Approval Dashboard Controller
 *
 * CRITICAL SECURITY RULES:
 * 1. Safe DOM updates: ALWAYS use `textContent` or DOM methods, NEVER unsafe HTML strings.
 * 2. Token Masking: NEVER display the raw full token on screen; keep token strictly in memory and provide "Copy token" button.
 * 3. Currency: Convert integer cents to formatted dollars ($XX.XX).
 */

const KNOWN_LEGIT_PAYEE = "STORE-ACCT-001";
let activePendingIds = new Set();
let pendingPollTimer = null;

// In-memory store for approved intents pending dismissal: id -> { token, expires_at, timerId, panelEl }
const approvedIntentsMemory = new Map();

document.addEventListener("DOMContentLoaded", () => {
    if (typeof initSystemStatus === "function") {
        initSystemStatus();
    }

    // Initial load
    fetchPendingIntents();
    fetchDecisionsHistory();

    // Auto-refresh polling every 2 seconds
    pendingPollTimer = setInterval(() => {
        fetchPendingIntents();
    }, 2000);

    const refreshHistoryBtn = document.getElementById("refresh-history-btn");
    if (refreshHistoryBtn) {
        refreshHistoryBtn.addEventListener("click", fetchDecisionsHistory);
    }
});

// Calculate live countdown string from epoch seconds
function formatCountdown(expiresAtSec) {
    const nowSec = Math.floor(Date.now() / 1000);
    const diff = expiresAtSec - nowSec;
    if (diff <= 0) return "Token expired";
    const mins = Math.floor(diff / 60);
    const secs = diff % 60;
    return `${mins}m ${secs < 10 ? "0" : ""}${secs}s remaining`;
}

// Poll pending approval requests
async function fetchPendingIntents() {
    try {
        const res = await fetch("/api/intents?status=pending");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const pendingIntents = await res.json();

        updatePendingCountBadge(pendingIntents.length);
        renderPendingCards(pendingIntents);
    } catch (err) {
        console.error("Failed to fetch pending intents:", err);
    }
}

// Update the pending count pill
function updatePendingCountBadge(count) {
    const badge = document.getElementById("pending-count-badge");
    if (badge) {
        badge.textContent = `${count} Pending`;
        if (count > 0) {
            badge.className = "badge badge-needs-review";
        } else {
            badge.className = "badge badge-pending";
        }
    }
}

// Render "Approval Required" cards safely using textContent, preserving approved confirmation panels
function renderPendingCards(intents) {
    const container = document.getElementById("pending-cards-container");
    if (!container) return;

    // Check if sub-containers exist; create if missing
    let approvedZone = document.getElementById("dashboard-approved-zone");
    let pendingZone = document.getElementById("dashboard-pending-zone");

    if (!approvedZone || !pendingZone) {
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }
        approvedZone = document.createElement("div");
        approvedZone.id = "dashboard-approved-zone";
        container.appendChild(approvedZone);

        pendingZone = document.createElement("div");
        pendingZone.id = "dashboard-pending-zone";
        container.appendChild(pendingZone);
    }

    // Check if pending IDs changed to avoid re-rendering untouched pending cards
    const newIds = new Set(intents.map((i) => i.id));
    const isSame = newIds.size === activePendingIds.size && [...newIds].every((id) => activePendingIds.has(id));
    if (isSame && intents.length > 0) {
        return;
    }
    activePendingIds = newIds;

    while (pendingZone.firstChild) {
        pendingZone.removeChild(pendingZone.firstChild);
    }

    if (intents.length === 0 && approvedIntentsMemory.size === 0) {
        const emptyDiv = document.createElement("div");
        emptyDiv.className = "empty-state";

        const icon = document.createElement("div");
        icon.className = "empty-state-icon";
        icon.textContent = "✅";
        emptyDiv.appendChild(icon);

        const text = document.createElement("div");
        text.className = "empty-state-text";
        text.textContent = "No pending approval requests.";
        emptyDiv.appendChild(text);

        const sub = document.createElement("p");
        sub.style.fontSize = "0.85rem";
        sub.style.color = "var(--text-muted)";
        sub.textContent = "Autonomous AI agents are idle. To trigger a pending intent, run scenario S5 in the Attack Demo.";
        emptyDiv.appendChild(sub);

        pendingZone.appendChild(emptyDiv);
        return;
    }

    intents.forEach((intent) => {
        const card = createApprovalCard(intent);
        pendingZone.appendChild(card);
    });
}

// Create an individual "Approval Required" card with large text for Agent and Merchant
function createApprovalCard(intent) {
    const card = document.createElement("div");
    card.className = "card";
    card.id = `card-${intent.id}`;
    card.style.marginTop = "1rem";
    card.style.border = "1px solid rgba(245, 158, 11, 0.4)";
    card.style.background = "rgba(15, 23, 42, 0.75)";

    // Card Header
    const cardHeader = document.createElement("div");
    cardHeader.className = "card-header";

    const titleDiv = document.createElement("div");
    titleDiv.className = "card-title";

    const warningIcon = document.createElement("span");
    warningIcon.textContent = "⚠️";
    titleDiv.appendChild(warningIcon);

    const titleText = document.createElement("span");
    titleText.textContent = `Approval Required: ${intent.item}`;
    titleDiv.appendChild(titleText);

    cardHeader.appendChild(titleDiv);

    // If payee is NOT STORE-ACCT-001 -> Highlight Red Alert Label
    const isUnrecognizedPayee = intent.payee_id !== KNOWN_LEGIT_PAYEE;
    if (isUnrecognizedPayee) {
        const alertTag = document.createElement("span");
        alertTag.className = "badge badge-blocked";
        alertTag.style.background = "rgba(239, 68, 68, 0.25)";
        alertTag.style.color = "#fca5a5";
        alertTag.style.border = "1px solid var(--danger)";
        alertTag.style.fontWeight = "700";
        alertTag.style.padding = "0.35rem 0.75rem";
        alertTag.textContent = "🚨 NEW PAYEE - check carefully";
        cardHeader.appendChild(alertTag);
    } else {
        const legitTag = document.createElement("span");
        legitTag.className = "badge badge-approved";
        legitTag.textContent = "Known Merchant Payee";
        cardHeader.appendChild(legitTag);
    }

    card.appendChild(cardHeader);

    // Card Body: Large text for Agent, Merchant, Item, Amount, Payee, and Summary
    const body = document.createElement("div");
    body.style.display = "grid";
    body.style.gridTemplateColumns = "repeat(auto-fit, minmax(min(100%, 220px), 1fr))";
    body.style.gap = "1.25rem";
    body.style.marginBottom = "1.25rem";

    // Item block (large text)
    body.appendChild(createDataBlock("Product / Item", intent.item, true));

    // Amount block (large text, converted from integer cents)
    const dollars = typeof formatCents === "function" ? formatCents(intent.amount_cents) : `$${(intent.amount_cents / 100).toFixed(2)}`;
    body.appendChild(createDataBlock("Amount", dollars, true, "var(--accent)"));

    // Payee block (large text, flagged if attacker)
    const payeeColor = isUnrecognizedPayee ? "#f87171" : "var(--text-primary)";
    body.appendChild(createDataBlock("Destination Payee", intent.payee_id, true, payeeColor));

    // Agent block (LARGE TEXT as explicitly required)
    body.appendChild(createDataBlock("Proposing Agent", intent.agent_id, true, "#38bdf8"));

    // Merchant block (LARGE TEXT as explicitly required)
    body.appendChild(createDataBlock("Merchant Store", intent.merchant_id, true, "#a78bfa"));

    card.appendChild(body);

    // Summary block
    const summaryBox = document.createElement("div");
    summaryBox.style.background = "rgba(0, 0, 0, 0.25)";
    summaryBox.style.border = "1px solid var(--border-subtle)";
    summaryBox.style.borderRadius = "var(--radius-sm)";
    summaryBox.style.padding = "0.85rem 1rem";
    summaryBox.style.marginBottom = "1.25rem";

    const summaryLabel = document.createElement("div");
    summaryLabel.style.fontSize = "0.75rem";
    summaryLabel.style.textTransform = "uppercase";
    summaryLabel.style.letterSpacing = "0.05em";
    summaryLabel.style.color = "var(--text-muted)";
    summaryLabel.style.marginBottom = "0.3rem";
    summaryLabel.textContent = "Agent Proposal Summary";
    summaryBox.appendChild(summaryLabel);

    const summaryContent = document.createElement("div");
    summaryContent.style.fontSize = "1rem";
    summaryContent.style.fontWeight = "500";
    summaryContent.style.color = "var(--text-primary)";
    summaryContent.textContent = intent.summary || "No summary provided by agent.";
    summaryBox.appendChild(summaryContent);

    card.appendChild(summaryBox);

    // Action Controls Container
    const actionRow = document.createElement("div");
    actionRow.id = `action-row-${intent.id}`;
    actionRow.style.display = "flex";
    actionRow.style.gap = "0.75rem";
    actionRow.style.flexWrap = "wrap";

    const approveBtn = document.createElement("button");
    approveBtn.className = "btn btn-success";
    approveBtn.type = "button";
    approveBtn.textContent = "✓ Approve & Issue Token";
    approveBtn.addEventListener("click", () => handleApprove(intent, card));
    actionRow.appendChild(approveBtn);

    const rejectBtn = document.createElement("button");
    rejectBtn.className = "btn btn-danger";
    rejectBtn.type = "button";
    rejectBtn.textContent = "✕ Reject Intent";
    rejectBtn.addEventListener("click", () => handleReject(intent.id, card));
    actionRow.appendChild(rejectBtn);

    card.appendChild(actionRow);

    return card;
}

// Helper to create a structured data block
function createDataBlock(label, value, isLarge = false, customColor = null) {
    const wrap = document.createElement("div");

    const lbl = document.createElement("div");
    lbl.style.fontSize = "0.75rem";
    lbl.style.textTransform = "uppercase";
    lbl.style.letterSpacing = "0.05em";
    lbl.style.color = "var(--text-muted)";
    lbl.style.marginBottom = "0.25rem";
    lbl.textContent = label;
    wrap.appendChild(lbl);

    const val = document.createElement("div");
    val.style.fontSize = isLarge ? "1.2rem" : "0.95rem";
    val.style.fontWeight = "700";
    val.style.color = customColor || "var(--text-primary)";
    val.textContent = value;
    wrap.appendChild(val);

    return wrap;
}

// Handle Approve Action: Keeps "Approved" confirmation panel on screen until dismissed
async function handleApprove(intent, cardEl) {
    const approveBtn = cardEl.querySelector(".btn-success");
    if (approveBtn) approveBtn.disabled = true;

    try {
        const res = await fetch(`/api/intents/${encodeURIComponent(intent.id)}/approve`, {
            method: "POST",
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Approval failed (${res.status})`);
        }

        const data = await res.json();
        const fullToken = data.token; // Keep full token strictly in memory
        const expiresAtSec = data.expires_at;

        // Remove card from pending zone
        cardEl.remove();
        activePendingIds.delete(intent.id);

        // Render Approved Confirmation Panel in approved zone
        renderApprovedConfirmationPanel(intent, fullToken, expiresAtSec);

        if (typeof showToast === "function") {
            showToast("Intent approved! Token created.", "success");
        }

        // Refresh decisions list and counter
        fetchDecisionsHistory();
        fetchPendingIntents();
    } catch (err) {
        if (approveBtn) approveBtn.disabled = false;
        if (typeof showToast === "function") {
            showToast(err.message, "danger");
        }
    }
}

// Render "Approved" confirmation panel that stays on screen until dismissed
function renderApprovedConfirmationPanel(intent, fullToken, expiresAtSec) {
    const approvedZone = document.getElementById("dashboard-approved-zone");
    if (!approvedZone) return;

    const panel = document.createElement("div");
    panel.className = "card";
    panel.id = `approved-panel-${intent.id}`;
    panel.style.marginTop = "1rem";
    panel.style.marginBottom = "1rem";
    panel.style.border = "2px solid rgba(16, 185, 129, 0.5)";
    panel.style.background = "linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(15, 23, 42, 0.85))";

    // Panel Header
    const header = document.createElement("div");
    header.className = "card-header";
    header.style.borderBottomColor = "rgba(16, 185, 129, 0.3)";

    const titleDiv = document.createElement("div");
    titleDiv.className = "card-title";
    titleDiv.style.color = "var(--success)";

    const okIcon = document.createElement("span");
    okIcon.textContent = "🛡️";
    titleDiv.appendChild(okIcon);

    const titleText = document.createElement("span");
    titleText.textContent = `Approved: ${intent.item}`;
    titleDiv.appendChild(titleText);

    header.appendChild(titleDiv);

    // Dismiss Button
    const dismissBtn = document.createElement("button");
    dismissBtn.className = "btn btn-secondary btn-sm";
    dismissBtn.type = "button";
    dismissBtn.textContent = "✕ Dismiss";
    dismissBtn.title = "Dismiss confirmation panel";
    header.appendChild(dismissBtn);

    panel.appendChild(header);

    // Summary Row
    const infoRow = document.createElement("div");
    infoRow.style.display = "flex";
    infoRow.style.gap = "1.5rem";
    infoRow.style.flexWrap = "wrap";
    infoRow.style.fontSize = "0.9rem";
    infoRow.style.marginBottom = "0.75rem";

    const dollars = typeof formatCents === "function" ? formatCents(intent.amount_cents) : `$${(intent.amount_cents / 100).toFixed(2)}`;
    infoRow.appendChild(createDataBlock("Amount", dollars, false, "var(--accent)"));
    infoRow.appendChild(createDataBlock("Payee", intent.payee_id, false));
    infoRow.appendChild(createDataBlock("Proposing Agent", intent.agent_id, false, "#38bdf8"));
    infoRow.appendChild(createDataBlock("Merchant Store", intent.merchant_id, false, "#a78bfa"));

    panel.appendChild(infoRow);

    // Expiry Notice Box with live countdown
    const expiryBox = document.createElement("div");
    expiryBox.style.background = "rgba(0, 0, 0, 0.3)";
    expiryBox.style.border = "1px solid rgba(16, 185, 129, 0.3)";
    expiryBox.style.borderRadius = "var(--radius-sm)";
    expiryBox.style.padding = "0.75rem 1rem";
    expiryBox.style.marginBottom = "1rem";

    const localTimeStr = new Date(expiresAtSec * 1000).toLocaleTimeString();
    const expiryLabel = document.createElement("div");
    expiryLabel.style.fontSize = "0.85rem";
    expiryLabel.style.color = "var(--text-secondary)";
    expiryLabel.textContent = `Token expires at ${localTimeStr} (local time)`;
    expiryBox.appendChild(expiryLabel);

    const countdownText = document.createElement("div");
    countdownText.style.fontSize = "1rem";
    countdownText.style.fontWeight = "700";
    countdownText.style.color = "var(--success)";
    countdownText.style.marginTop = "0.25rem";
    countdownText.textContent = `⏳ ${formatCountdown(expiresAtSec)}`;
    expiryBox.appendChild(countdownText);

    panel.appendChild(expiryBox);

    // Live 1-second countdown timer
    const countdownTimer = setInterval(() => {
        const remaining = formatCountdown(expiresAtSec);
        countdownText.textContent = `⏳ ${remaining}`;
        if (remaining === "Token expired") {
            countdownText.style.color = "var(--danger)";
        }
    }, 1000);

    // Actions Row: "Copy token" button (keeping token strictly in memory, never on screen)
    const btnRow = document.createElement("div");
    btnRow.style.display = "flex";
    btnRow.style.alignItems = "center";
    btnRow.style.gap = "0.75rem";
    btnRow.style.flexWrap = "wrap";

    const copyBtn = document.createElement("button");
    copyBtn.className = "btn btn-primary";
    copyBtn.type = "button";
    copyBtn.textContent = "Copy token";
    copyBtn.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(fullToken);
            copyBtn.textContent = "✓ Copied!";
            setTimeout(() => {
                copyBtn.textContent = "Copy token";
            }, 2000);
        } catch (clipErr) {
            // Textarea fallback
            const temp = document.createElement("textarea");
            temp.value = fullToken;
            document.body.appendChild(temp);
            temp.select();
            document.execCommand("copy");
            document.body.removeChild(temp);
            copyBtn.textContent = "✓ Copied!";
            setTimeout(() => {
                copyBtn.textContent = "Copy token";
            }, 2000);
        }
    });
    btnRow.appendChild(copyBtn);

    const memNotice = document.createElement("span");
    memNotice.style.fontSize = "0.8rem";
    memNotice.style.color = "var(--text-muted)";
    memNotice.textContent = "🔒 Full token held securely in memory (never written to screen).";
    btnRow.appendChild(memNotice);

    panel.appendChild(btnRow);

    // Dismiss click handler
    dismissBtn.addEventListener("click", () => {
        clearInterval(countdownTimer);
        approvedIntentsMemory.delete(intent.id);
        panel.remove();
        fetchPendingIntents();
    });

    // Store in memory
    approvedIntentsMemory.set(intent.id, {
        token: fullToken,
        expires_at: expiresAtSec,
        timer: countdownTimer,
        element: panel,
    });

    approvedZone.prepend(panel);
}

// Handle Reject Action
async function handleReject(intentId, cardEl) {
    const actionRow = document.getElementById(`action-row-${intentId}`);
    if (actionRow) actionRow.style.display = "none";

    try {
        const res = await fetch(`/api/intents/${encodeURIComponent(intentId)}/reject`, {
            method: "POST",
        });

        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.detail || `Rejection failed (${res.status})`);
        }

        cardEl.remove();
        activePendingIds.delete(intentId);

        if (typeof showToast === "function") {
            showToast("Intent successfully rejected", "warning");
        }

        setTimeout(() => {
            fetchDecisionsHistory();
            fetchPendingIntents();
        }, 500);
    } catch (err) {
        if (actionRow) actionRow.style.display = "flex";
        if (typeof showToast === "function") {
            showToast(err.message, "danger");
        }
    }
}

// Fetch resolved decisions history
async function fetchDecisionsHistory() {
    const tbody = document.getElementById("decisions-table-body");
    if (!tbody) return;

    try {
        const res = await fetch("/api/intents");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const allIntents = await res.json();

        // Filter for decided intents (approved or rejected)
        const decided = allIntents.filter((i) => i.status !== "pending");

        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

        if (decided.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 6;
            td.style.textAlign = "center";
            td.style.color = "var(--text-muted)";
            td.style.padding = "1.5rem";
            td.textContent = "No decisions recorded yet.";
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        decided.forEach((item) => {
            const tr = document.createElement("tr");

            // Col 1: Item
            const tdItem = document.createElement("td");
            tdItem.textContent = item.item;
            tdItem.style.fontWeight = "600";
            tr.appendChild(tdItem);

            // Col 2: Amount
            const tdAmt = document.createElement("td");
            tdAmt.textContent = typeof formatCents === "function" ? formatCents(item.amount_cents) : `$${(item.amount_cents / 100).toFixed(2)}`;
            tr.appendChild(tdAmt);

            // Col 3: Payee
            const tdPayee = document.createElement("td");
            tdPayee.textContent = item.payee_id;
            if (item.payee_id !== KNOWN_LEGIT_PAYEE) {
                tdPayee.style.color = "#f87171";
            }
            tr.appendChild(tdPayee);

            // Col 4: Merchant
            const tdMerch = document.createElement("td");
            tdMerch.textContent = item.merchant_id;
            tr.appendChild(tdMerch);

            // Col 5: Status
            const tdStatus = document.createElement("td");
            const badge = document.createElement("span");
            if (item.status === "approved") {
                badge.className = "badge badge-approved";
                badge.textContent = "Approved";
            } else {
                badge.className = "badge badge-rejected";
                badge.textContent = "Rejected";
            }
            tdStatus.appendChild(badge);
            tr.appendChild(tdStatus);

            // Col 6: Decided Time
            const tdTime = document.createElement("td");
            const ts = item.decided_at || item.created_at;
            tdTime.textContent = ts ? new Date(ts * 1000).toLocaleTimeString() : "—";
            tdTime.style.color = "var(--text-muted)";
            tdTime.style.fontSize = "0.85rem";
            tr.appendChild(tdTime);

            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load decisions history:", err);
    }
}
