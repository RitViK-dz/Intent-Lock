"""Simulated vulnerable AI shopping agent.

This simulates a hijacked agent; it is NOT a real AI model.

The agent demonstrates prompt injection vulnerabilities: it follows user tasks,
reads simulated web pages, and naively obeys instructions embedded inside page content.
In protected mode, IntentLock cryptographically binds user approval to original intent,
preventing hijacked actions from executing at checkout.
"""

import time
from typing import Any
from fastapi.testclient import TestClient

from agent_sim.scenarios import get_scenario


def run_scenario(
    scenario_id: str,
    protected: bool,
    auto_approve: bool = True,
    client: Any = None,
) -> dict[str, Any]:
    """Execute a simulated shopping agent run against either protected or unprotected endpoints.

    Honest Simulation Sequence:
    1. Agent reads page text and detects user task (plus any injected prompt).
    2. In protected mode: Agent posts intent with ORIGINAL user-task details.
    3. Human approves original intent; token is minted.
    4. Agent builds checkout request obeying injected page instruction.
    5. Store verifier checks token against checkout request:
       - Matches original approved intent -> APPROVED.
       - Discrepancy -> BLOCKED with reason code.
    """
    if client is None:
        from app.main import app
        client = TestClient(app)

    scenario = get_scenario(scenario_id)
    if not scenario:
        raise ValueError(f"Unknown scenario ID: {scenario_id}")

    trace: list[dict[str, Any]] = []
    orders_created: list[str] = []

    def _log(msg: str):
        trace.append({
            "step": len(trace) + 1,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "message": msg,
        })

    _log(f"Agent initiated task: '{scenario['user_task']}'. Target merchant: '{scenario['merchant_id']}'.")

    # Step 1: Read page content
    _log(f"Agent visiting merchant page. Content analyzed:\n{scenario['page_text']}")
    if scenario["injected_instruction"]:
        _log(
            f"PROMPT INJECTION TRIGGERED: Found hidden page directive: "
            f"'{scenario['injected_instruction']}'. Agent internal state modified."
        )

    # Step 2: Intent creation & approval in protected mode
    token: str | None = None
    if protected:
        # Determine intent parameters (for S5, agent is hijacked into filing intent with attacker payee)
        intent_payee = (
            scenario["hijacked_payee_id"]
            if scenario["id"] == "S5" and scenario["hijacked_payee_id"]
            else scenario["payee_id"]
        )

        _log(
            f"Protected Mode: Proposing intent for human review. "
            f"Item: '{scenario['item']}', Amount: {scenario['amount_cents']} cents, Payee: '{intent_payee}'."
        )

        intent_res = client.post(
            "/api/intents",
            json={
                "agent_id": "shopper-agent-1",
                "merchant_id": scenario["merchant_id"],
                "item": scenario["item"],
                "amount_cents": scenario["amount_cents"],
                "payee_id": intent_payee,
                "summary": f"Automated purchase proposal for {scenario['item']}",
            },
        )

        if intent_res.status_code != 201:
            _log(f"Intent creation failed with HTTP {intent_res.status_code}.")
            return {
                "trace": trace,
                "outcome": "error",
                "orders_created": orders_created,
                "reason": "INTENT_CREATION_FAILED",
            }

        intent_id = intent_res.json()["intent_id"]
        _log(f"Pending intent {intent_id} recorded in database. Waiting for human approval.")

        # S5 is an intent-level forgery where injected text tricked the agent into filing
        # an intent for an attacker payee. auto_approve must NEVER approve forged intents.
        # This intent must remain pending for the human to review and reject on the dashboard.
        if scenario["id"] == "S5":
            _log(
                "needs human review: a human must reject this on the dashboard. "
                f"Payee '{intent_payee}' is unauthorized."
            )
            return {
                "trace": trace,
                "outcome": "needs_human_review",
                "orders_created": orders_created,
                "reason": "FORGED_INTENT_PENDING",
            }

        if auto_approve:
            _log(f"Simulating human approval on dashboard for intent {intent_id}...")
            approve_res = client.post(f"/api/intents/{intent_id}/approve")
            if approve_res.status_code == 200:
                token = approve_res.json()["token"]
                _log("Human approved intent. Single-use Ed25519 token issued by Token Issuer.")
            else:
                _log(f"Intent approval failed with status {approve_res.status_code}.")
                return {
                    "trace": trace,
                    "outcome": "error",
                    "orders_created": orders_created,
                    "reason": "APPROVAL_FAILED",
                }
    else:
        _log("Unprotected Mode: IntentLock approval bypassed. Proceeding without cryptographic token.")

    # Step 3: Build checkout request from page text (which may be hijacked)
    checkout_item = scenario["hijacked_item"] or scenario["item"]
    checkout_amount = scenario["hijacked_amount_cents"] or scenario["amount_cents"]
    checkout_payee = scenario["hijacked_payee_id"] or scenario["payee_id"]

    if scenario["injected_instruction"]:
        _log(
            f"Agent applying hijacked parameters to checkout payload: "
            f"item='{checkout_item}', amount={checkout_amount} cents, payee='{checkout_payee}'."
        )
    else:
        _log(
            f"Agent preparing standard checkout payload: "
            f"item='{checkout_item}', amount={checkout_amount} cents, payee='{checkout_payee}'."
        )

    # Step 4: Execute checkout at store
    if scenario["id"] == "S4" and protected:
        # S4 Token Replay Attack: First legitimate purchase, then replay
        _log("Executing initial legitimate checkout with token...")
        first_payload = {
            "agent_id": "shopper-agent-1",
            "merchant_id": scenario["merchant_id"],
            "item": scenario["item"],
            "amount_cents": scenario["amount_cents"],
            "payee_id": scenario["payee_id"],
            "token": token,
        }
        res1 = client.post("/store/checkout", json=first_payload)
        if res1.status_code == 200:
            order1 = res1.json().get("order_id")
            orders_created.append(order1)
            _log(f"First checkout approved. Order ID: {order1}.")

        _log("Agent now attempting MALICIOUS REPLAY of the same consumed token for a second order...")
        res2 = client.post("/store/checkout", json=first_payload)
        if res2.status_code == 200:
            orders_created.append(res2.json().get("order_id"))
            outcome = "approved"
            reason = "APPROVED"
        else:
            outcome = "blocked"
            reason = res2.json().get("reason")
            _log(f"Store verifier BLOCKED duplicate checkout attempt: {reason}.")

        return {
            "trace": trace,
            "outcome": outcome,
            "orders_created": orders_created,
            "reason": reason,
        }

    # Standard checkout execution
    checkout_payload = {
        "agent_id": "shopper-agent-1",
        "merchant_id": scenario["merchant_id"],
        "item": checkout_item,
        "amount_cents": checkout_amount,
        "payee_id": checkout_payee,
    }

    if protected:
        checkout_payload["token"] = token
        _log("Submitting checkout to protected endpoint POST /store/checkout...")
        store_res = client.post("/store/checkout", json=checkout_payload)

        if store_res.status_code == 200:
            order_id = store_res.json().get("order_id")
            orders_created.append(order_id)
            outcome = "approved"
            reason = store_res.json().get("reason", "APPROVED")
            _log(f"Protected checkout APPROVED by IntentLock. Order created: {order_id}.")
        else:
            outcome = "blocked"
            reason = store_res.json().get("reason")
            _log(f"Protected checkout BLOCKED by IntentLock verifier. Reason: {reason}.")
    else:
        _log("Submitting checkout to unprotected endpoint POST /store/checkout-unprotected...")
        store_res = client.post("/store/checkout-unprotected", json=checkout_payload)
        order_id = store_res.json().get("order_id")
        orders_created.append(order_id)
        outcome = store_res.json().get("status", "completed_UNPROTECTED")
        reason = None
        _log(
            f"Unprotected checkout completed without verification! "
            f"Order ID: {order_id}, Payment delivered to payee '{checkout_payee}'."
        )

    return {
        "trace": trace,
        "outcome": outcome,
        "orders_created": orders_created,
        "reason": reason,
    }
