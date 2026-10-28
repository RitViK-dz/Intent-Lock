/**
 * IntentLock - Live Security Audit Log Viewer Controller
 *
 * CRITICAL SECURITY RULES:
 * 1. Safe DOM updates: ALWAYS use `textContent` or DOM methods, NEVER unsafe HTML strings.
 * 2. Visual Differentiation: Green rows for allowed actions, red rows for blocked actions.
 * 3. Token Privacy: Confirms raw tokens are absent from audit displays.
 */

let auditPollTimer = null;

document.addEventListener("DOMContentLoaded", () => {
    if (typeof initSystemStatus === "function") {
        initSystemStatus();
    }

    // Initial fetch
    fetchAuditLogs();

    // Auto-refresh every 2 seconds
    auditPollTimer = setInterval(fetchAuditLogs, 2000);
});

// Fetch audit records from GET /api/audit
async function fetchAuditLogs() {
    const tbody = document.getElementById("audit-table-body");
    const countBadge = document.getElementById("audit-count-badge");
    if (!tbody) return;

    try {
        const res = await fetch("/api/audit");
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const entries = await res.json();

        if (countBadge) {
            countBadge.textContent = `${entries.length} Events`;
        }

        while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

        if (entries.length === 0) {
            const tr = document.createElement("tr");
            const td = document.createElement("td");
            td.colSpan = 4;
            td.style.textAlign = "center";
            td.style.color = "var(--text-muted)";
            td.style.padding = "2rem";
            td.textContent = "No audit log entries recorded yet.";
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }

        entries.forEach((entry) => {
            const tr = document.createElement("tr");

            // Extract details safely
            const detail = entry.detail || {};
            const isAllowed = entry.event === "checkout_allowed" || detail.allowed === true || detail.reason === "APPROVED";
            const isBlocked = entry.event === "checkout_blocked" || detail.allowed === false || (detail.reason && detail.reason !== "APPROVED");

            // Visual row styling: green rows for allowed, red rows for blocked
            if (isAllowed) {
                tr.style.backgroundColor = "rgba(16, 185, 129, 0.12)";
                tr.style.color = "#a7f3d0";
            } else if (isBlocked) {
                tr.style.backgroundColor = "rgba(239, 68, 68, 0.12)";
                tr.style.color = "#fca5a5";
            }

            // Col 1: Time
            const tdTime = document.createElement("td");
            tdTime.style.whiteSpace = "nowrap";
            tdTime.style.fontSize = "0.85rem";
            tdTime.textContent = entry.ts ? new Date(entry.ts * 1000).toLocaleTimeString() : "—";
            tr.appendChild(tdTime);

            // Col 2: Event
            const tdEvent = document.createElement("td");
            const eventBadge = document.createElement("span");
            eventBadge.className = "badge";
            if (isAllowed) {
                eventBadge.classList.add("badge-approved");
            } else if (isBlocked) {
                eventBadge.classList.add("badge-blocked");
            } else if (entry.event === "intent_created") {
                eventBadge.classList.add("badge-pending");
            } else {
                eventBadge.classList.add("badge-protected");
            }
            eventBadge.textContent = entry.event || "unknown_event";
            tdEvent.appendChild(eventBadge);
            tr.appendChild(tdEvent);

            // Col 3: Reason Code
            const tdReason = document.createElement("td");
            const reasonCode = detail.reason || detail.status || (isAllowed ? "APPROVED" : "—");
            const reasonSpan = document.createElement("span");
            reasonSpan.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
            reasonSpan.style.fontSize = "0.85rem";
            reasonSpan.style.fontWeight = "600";
            reasonSpan.textContent = reasonCode;
            tdReason.appendChild(reasonSpan);
            tr.appendChild(tdReason);

            // Col 4: Summary / Details
            const tdSummary = document.createElement("td");
            tdSummary.style.fontSize = "0.85rem";
            tdSummary.style.wordBreak = "break-word";
            tdSummary.style.overflowWrap = "anywhere";

            let summaryText = "";
            if (detail.summary) {
                summaryText = detail.summary;
            } else if (entry.event.startsWith("checkout")) {
                const item = detail.item || "item";
                const amt = detail.amount_cents ? `$${(detail.amount_cents / 100).toFixed(2)}` : "";
                const payee = detail.payee_id || "";
                summaryText = `Checkout attempt for ${item} ${amt ? `(${amt})` : ""} -> Payee: ${payee}`;
            } else if (entry.event === "intent_approved") {
                summaryText = `Intent ${entry.intent_id || ""} approved by ${entry.actor || "human"}. Token minted.`;
            } else if (entry.event === "intent_rejected") {
                summaryText = `Intent ${entry.intent_id || ""} rejected by ${entry.actor || "human"}.`;
            } else {
                summaryText = `Actor: ${entry.actor || "system"} • Intent: ${entry.intent_id || "none"}`;
            }

            tdSummary.textContent = summaryText;
            tr.appendChild(tdSummary);

            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error("Failed to load audit records:", err);
    }
}
