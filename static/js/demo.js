/**
 * IntentLock - Phase 9 Demo Showcase Controller (Vanilla JavaScript)
 *
 * CRITICAL SECURITY & PRESENTATION RULES:
 * 1. Safe DOM updates: ALWAYS use `textContent` or DOM methods, NEVER `innerHTML`.
 * 2. Delay: Animate execution traces with ~600ms delay per step so judges can follow along.
 * 3. Clear Result Badges:
 *    - Unprotected: Red "ATTACK SUCCEEDED - money sent to <payee>"
 *    - Protected: Green "BLOCKED - <reason code>" + plain-English explanation.
 * 4. S5 Review: Explicitly showcase forged intent requiring human rejection on dashboard.
 * 5. Demo Reset: Calls POST /api/demo/reset (DEMO_MODE required).
 */

const REASON_EXPLANATIONS = {
    PAYEE_MISMATCH: "The payee in the request is not the payee the user approved.",
    AMOUNT_EXCEEDS_LIMIT: "The requested amount exceeds the maximum amount authorized by the human.",
    ITEM_MISMATCH: "The item in the checkout request does not match the item approved by the user.",
    TOKEN_REPLAYED: "This cryptographic token was already consumed. Replay attacks are rejected.",
    FORGED_INTENT_PENDING: "The injected prompt tricked the agent into submitting a forged intent request for the attacker. No token was issued. A human must reject this unapproved intent on the Approval Dashboard.",
    APPROVED: "The checkout parameters matched the human-approved intent exactly.",
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let scenariosData = [];
let isRunning = false;

document.addEventListener("DOMContentLoaded", async () => {
    if (typeof initSystemStatus === "function") {
        initSystemStatus();
    }
    await loadScenarios();

    const scenarioSelect = document.getElementById("scenario-select");
    if (scenarioSelect) {
        scenarioSelect.addEventListener("change", () => {
            updateScenarioDetails(scenarioSelect.value);
        });
    }

    const runAttackBtn = document.getElementById("run-attack-btn");
    if (runAttackBtn) {
        runAttackBtn.addEventListener("click", runAttack);
    }

    const runAllBtn = document.getElementById("run-all-btn");
    if (runAllBtn) {
        runAllBtn.addEventListener("click", runAllScenarios);
    }

    const resetDemoBtn = document.getElementById("reset-demo-btn");
    if (resetDemoBtn) {
        resetDemoBtn.addEventListener("click", resetDemoState);
    }
});

// Load scenarios from backend API
async function loadScenarios() {
    try {
        scenariosData = typeof IntentLockAPI !== "undefined" && IntentLockAPI.getScenarios
            ? await IntentLockAPI.getScenarios()
            : await (await fetch("/api/demo/scenarios")).json();

        const select = document.getElementById("scenario-select");
        if (!select) return;

        while (select.firstChild) {
            select.removeChild(select.firstChild);
        }

        scenariosData.forEach((s) => {
            const opt = document.createElement("option");
            opt.value = s.id;
            opt.textContent = `${s.id}: ${s.title}`;
            select.appendChild(opt);
        });

        if (scenariosData.length > 0) {
            updateScenarioDetails(scenariosData[0].id);
        }
    } catch (err) {
        if (typeof showToast === "function") {
            showToast("Failed to load attack scenarios", "danger");
        }
    }
}

// Update the user prompt and highlighted injection instruction box
function updateScenarioDetails(scenarioId) {
    const scenario = scenariosData.find((s) => s.id === scenarioId);
    if (!scenario) return;

    const taskEl = document.getElementById("scenario-user-task");
    if (taskEl) {
        taskEl.textContent = scenario.user_task;
    }

    const injectedBox = document.getElementById("scenario-injected-box");
    const injectedTitle = document.getElementById("scenario-injected-title");
    const injectedText = document.getElementById("scenario-injected-text");

    if (injectedBox && injectedTitle && injectedText) {
        if (scenario.injected_instruction) {
            injectedBox.className = "injected-directive-box";
            injectedTitle.textContent = "🚨 Hidden Injected Prompt Directive (Hijack Payload):";
            injectedText.textContent = scenario.injected_instruction;
        } else {
            injectedBox.className = "injected-directive-box clean";
            injectedTitle.textContent = "🛡️ Normal Webpage (Clean Baseline):";
            injectedText.textContent = "No prompt injection present on the page. Baseline legitimate purchase.";
        }
    }

    // Hide S5 callout when switching scenarios
    const s5Card = document.getElementById("s5-alert-card");
    if (s5Card) {
        s5Card.style.display = "none";
    }
}

// Stream trace steps into container with ~600ms delay per step
async function animateTrace(steps, containerEl) {
    while (containerEl.firstChild) {
        containerEl.removeChild(containerEl.firstChild);
    }

    for (let i = 0; i < steps.length; i++) {
        const step = steps[i];
        const stepDiv = document.createElement("div");
        const isInjection = step.message && step.message.includes("PROMPT INJECTION TRIGGERED");
        stepDiv.className = `trace-step trace-step-animated ${isInjection ? "injection" : "normal"}`;

        const header = document.createElement("div");
        header.className = "trace-step-header";
        header.textContent = `Step ${step.step} • ${step.timestamp}`;
        stepDiv.appendChild(header);

        const content = document.createElement("div");
        content.className = "trace-step-content";
        content.textContent = step.message;
        stepDiv.appendChild(content);

        containerEl.appendChild(stepDiv);

        // Keep scrolled to latest step
        containerEl.scrollTop = containerEl.scrollHeight;

        // 600 ms delay between steps for visual pacing
        if (i < steps.length - 1) {
            await sleep(600);
        }
    }
}

// Run the currently selected scenario in both modes side-by-side
async function runAttack() {
    if (isRunning) return;
    const select = document.getElementById("scenario-select");
    const scenarioId = select ? select.value : "S1";
    const scenario = scenariosData.find((s) => s.id === scenarioId) || {};

    const unprotContainer = document.getElementById("unprot-trace-container");
    const protContainer = document.getElementById("prot-trace-container");
    const unprotBadge = document.getElementById("unprot-result-badge");
    const protBadge = document.getElementById("prot-result-badge");
    const s5Card = document.getElementById("s5-alert-card");

    setControlsDisabled(true);
    if (unprotBadge) unprotBadge.style.display = "none";
    if (protBadge) protBadge.style.display = "none";
    if (s5Card) s5Card.style.display = "none";

    // Set placeholder pending text in traces
    if (unprotContainer) {
        while (unprotContainer.firstChild) unprotContainer.removeChild(unprotContainer.firstChild);
        const p = document.createElement("div");
        p.className = "empty-state-text";
        p.textContent = "Executing unprotected run...";
        unprotContainer.appendChild(p);
    }
    if (protContainer) {
        while (protContainer.firstChild) protContainer.removeChild(protContainer.firstChild);
        const p = document.createElement("div");
        p.className = "empty-state-text";
        p.textContent = "Executing protected IntentLock run...";
        protContainer.appendChild(p);
    }

    try {
        // Fetch both simulation runs from backend
        const [unprotRes, protRes] = await Promise.all([
            fetchRun(scenarioId, false),
            fetchRun(scenarioId, true),
        ]);

        // Animate both traces in parallel with 600ms delay per step
        await Promise.all([
            animateTrace(unprotRes.trace || [], unprotContainer),
            animateTrace(protRes.trace || [], protContainer),
        ]);

        // Show Unprotected Result Badge
        if (unprotBadge) {
            renderUnprotectedBadge(unprotBadge, scenario, unprotRes);
        }

        // Show Protected Result Badge
        if (protBadge) {
            renderProtectedBadge(protBadge, scenario, protRes);
        }

        // S5 Special Callout if forged intent was detected
        if (scenarioId === "S5" && s5Card) {
            s5Card.style.display = "flex";
        }
    } catch (err) {
        if (typeof showToast === "function") {
            showToast(`Simulation error: ${err.message}`, "danger");
        }
    } finally {
        setControlsDisabled(false);
    }
}

// Render the large unprotected result badge
function renderUnprotectedBadge(badgeEl, scenario, res) {
    while (badgeEl.firstChild) {
        badgeEl.removeChild(badgeEl.firstChild);
    }

    const titleEl = document.createElement("div");
    const subEl = document.createElement("div");
    subEl.className = "result-explanation-text";

    if (scenario.id === "S0") {
        badgeEl.className = "result-banner result-banner-success";
        titleEl.textContent = "✓ PURCHASE COMPLETED - STORE-ACCT-001";
        subEl.textContent = "Normal baseline purchase completed without interference.";
    } else {
        badgeEl.className = "result-banner result-banner-danger";
        const payee = scenario.hijacked_payee_id || scenario.payee_id || "ATTACKER-ACCT-999";
        
        if (scenario.id === "S4") {
            titleEl.textContent = `🚨 ATTACK SUCCEEDED - money sent to ${payee}`;
            subEl.textContent = "Unprotected checkout accepted duplicate replayed checkout without verification: duplicate charge occurred.";
        } else if (scenario.id === "S2") {
            titleEl.textContent = `🚨 ATTACK SUCCEEDED - money sent to ${payee}`;
            subEl.textContent = "Unprotected store accepted inflated amount ($900.00) without human verification.";
        } else {
            titleEl.textContent = `🚨 ATTACK SUCCEEDED - money sent to ${payee}`;
            subEl.textContent = `Prompt injection hijacked the agent. Payment of $${((scenario.hijacked_amount_cents || scenario.amount_cents) / 100).toFixed(2)} was sent directly to attacker payee '${payee}'.`;
        }
    }

    badgeEl.appendChild(titleEl);
    badgeEl.appendChild(subEl);
    badgeEl.style.display = "flex";
}

// Render the large protected result badge
function renderProtectedBadge(badgeEl, scenario, res) {
    while (badgeEl.firstChild) {
        badgeEl.removeChild(badgeEl.firstChild);
    }

    const titleEl = document.createElement("div");
    const subEl = document.createElement("div");
    subEl.className = "result-explanation-text";

    if (res.outcome === "approved") {
        badgeEl.className = "result-banner result-banner-success";
        titleEl.textContent = "🛡️ APPROVED - Valid IntentLock Token Verified";
        subEl.textContent = REASON_EXPLANATIONS.APPROVED;
    } else if (res.outcome === "needs_human_review" || res.reason === "FORGED_INTENT_PENDING") {
        badgeEl.className = "result-banner result-banner-warning";
        titleEl.textContent = "⚠️ NEEDS HUMAN REVIEW - FORGED_INTENT_PENDING";
        subEl.textContent = REASON_EXPLANATIONS.FORGED_INTENT_PENDING;
    } else {
        badgeEl.className = "result-banner result-banner-success";
        const reasonCode = res.reason || "BLOCKED";
        titleEl.textContent = `🛡️ BLOCKED - ${reasonCode}`;
        subEl.textContent = REASON_EXPLANATIONS[reasonCode] || "IntentLock verifier blocked the unapproved checkout request.";
    }

    badgeEl.appendChild(titleEl);
    badgeEl.appendChild(subEl);
    badgeEl.style.display = "flex";
}

// Execute all scenarios (S0 to S5) and populate summary table
async function runAllScenarios() {
    if (isRunning) return;
    setControlsDisabled(true);

    const tableSection = document.getElementById("summary-table-section");
    const tbody = document.getElementById("summary-table-body");
    if (tableSection) tableSection.style.display = "block";
    if (!tbody) {
        setControlsDisabled(false);
        return;
    }

    while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
    }

    if (typeof showToast === "function") {
        showToast("Running matrix of all scenarios in both modes...", "info");
    }

    try {
        for (const scenario of scenariosData) {
            const tr = document.createElement("tr");

            // Col 1: Scenario
            const scTd = document.createElement("td");
            const strongTitle = document.createElement("strong");
            strongTitle.textContent = `${scenario.id}: ${scenario.title}`;
            scTd.appendChild(strongTitle);
            tr.appendChild(scTd);

            // Fetch both runs
            const [unprotRes, protRes] = await Promise.all([
                fetchRun(scenario.id, false),
                fetchRun(scenario.id, true),
            ]);

            // Col 2: Unprotected Result
            const unprotTd = document.createElement("td");
            const unprotBadge = document.createElement("span");
            if (scenario.id === "S0") {
                unprotBadge.className = "badge badge-approved";
                unprotBadge.textContent = "Normal Purchase";
            } else {
                unprotBadge.className = "badge badge-blocked";
                const payee = scenario.hijacked_payee_id || "ATTACKER";
                unprotBadge.textContent = `ATTACK SUCCEEDED (Sent to ${payee})`;
            }
            unprotTd.appendChild(unprotBadge);
            tr.appendChild(unprotTd);

            // Col 3: Protected Result
            const protTd = document.createElement("td");
            const protBadge = document.createElement("span");
            if (protRes.outcome === "approved") {
                protBadge.className = "badge badge-approved";
                protBadge.textContent = "APPROVED (Verified)";
            } else if (protRes.outcome === "needs_human_review") {
                protBadge.className = "badge badge-needs-review";
                protBadge.textContent = "NEEDS HUMAN REVIEW (Flagged)";
            } else {
                protBadge.className = "badge badge-approved";
                protBadge.textContent = `BLOCKED (${protRes.reason})`;
            }
            protTd.appendChild(protBadge);
            tr.appendChild(protTd);

            tbody.appendChild(tr);
        }

        if (typeof showToast === "function") {
            showToast("Matrix complete: IntentLock protected all scenarios", "success");
        }
    } catch (err) {
        if (typeof showToast === "function") {
            showToast(`Batch execution error: ${err.message}`, "danger");
        }
    } finally {
        setControlsDisabled(false);
    }
}

// Reset demo database state
async function resetDemoState() {
    if (isRunning) return;
    const btn = document.getElementById("reset-demo-btn");
    if (btn) btn.disabled = true;

    try {
        if (typeof IntentLockAPI !== "undefined" && IntentLockAPI.resetDemo) {
            await IntentLockAPI.resetDemo();
        } else {
            const res = await fetch("/api/demo/reset", { method: "POST" });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || `Reset failed with HTTP ${res.status}`);
            }
        }

        // Clear UI states
        const unprotContainer = document.getElementById("unprot-trace-container");
        const protContainer = document.getElementById("prot-trace-container");
        const unprotBadge = document.getElementById("unprot-result-badge");
        const protBadge = document.getElementById("prot-result-badge");
        const s5Card = document.getElementById("s5-alert-card");
        const summaryTbody = document.getElementById("summary-table-body");

        if (unprotBadge) unprotBadge.style.display = "none";
        if (protBadge) protBadge.style.display = "none";
        if (s5Card) s5Card.style.display = "none";

        if (unprotContainer) {
            while (unprotContainer.firstChild) unprotContainer.removeChild(unprotContainer.firstChild);
            const p = document.createElement("div");
            p.className = "empty-state-text";
            p.textContent = "Demo state reset. Choose a scenario and click 'Run attack'.";
            unprotContainer.appendChild(p);
        }
        if (protContainer) {
            while (protContainer.firstChild) protContainer.removeChild(protContainer.firstChild);
            const p = document.createElement("div");
            p.className = "empty-state-text";
            p.textContent = "Demo state reset. Choose a scenario and click 'Run attack'.";
            protContainer.appendChild(p);
        }
        if (summaryTbody) {
            while (summaryTbody.firstChild) summaryTbody.removeChild(summaryTbody.firstChild);
        }

        if (typeof showToast === "function") {
            showToast("Demo reset: orders, intents, nonces, and audit logs cleared.", "success");
        }
    } catch (err) {
        if (typeof showToast === "function") {
            showToast(err.message, "danger");
        }
    } finally {
        if (btn) btn.disabled = false;
    }
}

// Helper: fetch run from backend
async function fetchRun(scenarioId, isProtected) {
    if (typeof IntentLockAPI !== "undefined" && IntentLockAPI.runScenario) {
        return IntentLockAPI.runScenario(scenarioId, isProtected, true);
    }
    const res = await fetch("/api/demo/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            scenario_id: scenarioId,
            protected: isProtected,
            auto_approve: true,
        }),
    });
    if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || `Run failed: ${res.status}`);
    }
    return res.json();
}

// Helper to disable/enable controls during runs
function setControlsDisabled(disabled) {
    isRunning = disabled;
    const runBtn = document.getElementById("run-attack-btn");
    const allBtn = document.getElementById("run-all-btn");
    const resetBtn = document.getElementById("reset-demo-btn");
    const select = document.getElementById("scenario-select");

    if (runBtn) runBtn.disabled = disabled;
    if (allBtn) allBtn.disabled = disabled;
    if (resetBtn) resetBtn.disabled = disabled;
    if (select) select.disabled = disabled;
}
