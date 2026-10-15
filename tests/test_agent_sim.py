"""Tests for the simulated AI agent and prompt injection attack scenarios."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import init_db
from app.config import settings
from agent_sim.scenarios import get_scenario, list_scenarios
from agent_sim.naive_agent import run_scenario

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path):
    """Ensure tests run against isolated clean test database and keys."""
    test_db = tmp_path / "test_sim.db"
    init_db(test_db)
    test_keys = tmp_path / "keys"

    orig_db = settings.db_path
    orig_keys = settings.keys_dir
    object.__setattr__(settings, "db_path", test_db)
    object.__setattr__(settings, "keys_dir", test_keys)
    yield
    object.__setattr__(settings, "db_path", orig_db)
    object.__setattr__(settings, "keys_dir", orig_keys)


def test_naive_agent_docstring_honesty_statement():
    """Verify naive_agent.py explicitly states it is a simulation and not a real AI model."""
    import agent_sim.naive_agent as agent_module

    doc = agent_module.__doc__ or ""
    assert "This simulates a hijacked agent; it is NOT a real AI model." in doc


def test_scenario_catalog():
    """Verify all scenarios S0 through S5 are defined with expected metadata."""
    scenarios = list_scenarios()
    scenario_ids = [s["id"] for s in scenarios]

    for expected_id in ["S0", "S1", "S2", "S3", "S4", "S5"]:
        assert expected_id in scenario_ids

    s1 = get_scenario("S1")
    assert s1 is not None
    assert "ATTACKER-ACCT-999" in s1["hijacked_payee_id"]


def test_s0_clean_purchase_allowed_in_both_modes():
    """S0 clean purchase succeeds in both unprotected and protected modes."""
    # Unprotected mode
    unprot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S0", "protected": False, "auto_approve": True},
    )
    assert unprot_res.status_code == 200
    unprot_data = unprot_res.json()
    assert unprot_data["outcome"] == "completed_UNPROTECTED"
    assert len(unprot_data["orders_created"]) == 1

    # Protected mode
    prot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S0", "protected": True, "auto_approve": True},
    )
    assert prot_res.status_code == 200
    prot_data = prot_res.json()
    assert prot_data["outcome"] == "approved"
    assert prot_data["reason"] == "APPROVED"
    assert len(prot_data["orders_created"]) == 1


def test_s1_recipient_swap_attack():
    """S1 recipient swap succeeds unprotected (money diverted) and is blocked in protected mode."""
    # Unprotected mode: payment diverted to attacker
    unprot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S1", "protected": False, "auto_approve": True},
    )
    assert unprot_res.status_code == 200
    unprot_data = unprot_res.json()
    # Confirm order was completed to the attacker account in database
    orders = client.get("/store/orders").json()
    assert any(o["payee_id"] == "ATTACKER-ACCT-999" for o in orders)
    assert any("ATTACKER-ACCT-999" in t["message"] for t in unprot_data["trace"])

    # Protected mode: IntentLock verifier catches payee mismatch
    prot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S1", "protected": True, "auto_approve": True},
    )
    assert prot_res.status_code == 200
    prot_data = prot_res.json()
    assert prot_data["outcome"] == "blocked"
    assert prot_data["reason"] == "PAYEE_MISMATCH"


def test_s2_amount_inflation_attack():
    """S2 amount inflation succeeds unprotected and is blocked with AMOUNT_EXCEEDS_LIMIT."""
    # Unprotected mode: allows inflated price
    unprot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S2", "protected": False, "auto_approve": True},
    )
    assert unprot_res.status_code == 200
    assert unprot_res.json()["outcome"] == "completed_UNPROTECTED"

    # Protected mode: blocked by IntentLock ceiling check
    prot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S2", "protected": True, "auto_approve": True},
    )
    assert prot_res.status_code == 200
    prot_data = prot_res.json()
    assert prot_data["outcome"] == "blocked"
    assert prot_data["reason"] == "AMOUNT_EXCEEDS_LIMIT"


def test_s3_item_swap_attack():
    """S3 item swap succeeds unprotected and is blocked with ITEM_MISMATCH in protected mode."""
    # Unprotected mode
    unprot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S3", "protected": False, "auto_approve": True},
    )
    assert unprot_res.status_code == 200
    assert unprot_res.json()["outcome"] == "completed_UNPROTECTED"

    # Protected mode: blocked by IntentLock item check
    prot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S3", "protected": True, "auto_approve": True},
    )
    assert prot_res.status_code == 200
    prot_data = prot_res.json()
    assert prot_data["outcome"] == "blocked"
    assert prot_data["reason"] == "ITEM_MISMATCH"


def test_s4_token_replay_attack():
    """S4 token replay: protected mode blocks duplicate as TOKEN_REPLAYED; unprotected places duplicate order."""
    # 1. Protected Mode: duplicate checkout is blocked
    prot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S4", "protected": True, "auto_approve": True},
    )
    assert prot_res.status_code == 200
    prot_data = prot_res.json()
    assert prot_data["outcome"] == "blocked"
    assert prot_data["reason"] == "TOKEN_REPLAYED"
    # First checkout succeeded, second duplicate was blocked
    assert len(prot_data["orders_created"]) == 1

    # 2. Unprotected Mode: duplicate checkout succeeds, creating two orders
    unprot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S4", "protected": False, "auto_approve": True},
    )
    assert unprot_res.status_code == 200
    unprot_data = unprot_res.json()
    assert unprot_data["outcome"] == "completed_UNPROTECTED"
    assert len(unprot_data["orders_created"]) == 2

    # Check store orders to confirm duplicate charges exist in unprotected mode
    orders = client.get("/store/orders").json()
    unprot_s4_orders = [o for o in orders if o["id"] in unprot_data["orders_created"]]
    assert len(unprot_s4_orders) == 2
    assert all(o["endpoint"] == "unprotected" for o in unprot_s4_orders)


def test_get_demo_scenarios_endpoint():
    """Verify GET /api/demo/scenarios returns all scenarios."""
    response = client.get("/api/demo/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) >= 6


def test_s5_forged_approval_request_protected_and_unprotected():
    """Verify S5 behavior: protected leaves forged intent pending for human review; unprotected pays attacker."""
    # 1. S5 in Protected Mode
    prot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S5", "protected": True, "auto_approve": True},
    )
    assert prot_res.status_code == 200
    prot_data = prot_res.json()
    assert prot_data["outcome"] == "needs_human_review"
    assert prot_data["reason"] == "FORGED_INTENT_PENDING"
    assert any("needs human review: a human must reject this on the dashboard" in t["message"] for t in prot_data["trace"])
    assert len(prot_data["orders_created"]) == 0

    # Verify: no order has payee ATTACKER-ACCT-999 with endpoint protected
    orders = client.get("/store/orders").json()
    assert not any(o["payee_id"] == "ATTACKER-ACCT-999" and o["endpoint"] == "protected" for o in orders)

    # Verify: exactly one pending intent for the attacker exists
    pending_intents = client.get("/api/intents?status=pending").json()
    attacker_intents = [i for i in pending_intents if i["payee_id"] == "ATTACKER-ACCT-999"]
    assert len(attacker_intents) == 1

    # 2. S5 in Unprotected Mode: proceeds straight to unprotected store and pays attacker
    unprot_res = client.post(
        "/api/demo/run",
        json={"scenario_id": "S5", "protected": False, "auto_approve": True},
    )
    assert unprot_res.status_code == 200
    unprot_data = unprot_res.json()
    assert unprot_data["outcome"] == "completed_UNPROTECTED"
    assert len(unprot_data["orders_created"]) == 1

    orders_after = client.get("/store/orders").json()
    assert any(o["payee_id"] == "ATTACKER-ACCT-999" and o["endpoint"] == "unprotected" for o in orders_after)


def test_all_scenarios_protected_orders_payee_integrity():
    """Verify running S0 to S5 in protected mode on a clean DB results ONLY in orders with payee STORE-ACCT-001."""
    # Execute scenarios S0 through S5 in protected mode
    for sid in ["S0", "S1", "S2", "S3", "S4", "S5"]:
        res = client.post(
            "/api/demo/run",
            json={"scenario_id": sid, "protected": True, "auto_approve": True},
        )
        assert res.status_code == 200

    # Retrieve all completed orders
    orders_res = client.get("/store/orders")
    assert orders_res.status_code == 200
    all_orders = orders_res.json()

    # Filter orders created through the protected endpoint
    protected_orders = [o for o in all_orders if o["endpoint"] == "protected"]

    # Verify orders were created (from S0 and the first legitimate transaction of S4)
    assert len(protected_orders) >= 2

    # CRITICAL INVARIANT: Every single protected order must have payee STORE-ACCT-001
    for order in protected_orders:
        assert order["payee_id"] == "STORE-ACCT-001", (
            f"Protected order {order['id']} had unexpected payee: {order['payee_id']}"
        )

    # Confirm zero protected orders were sent to any attacker account
    assert not any(o["payee_id"] != "STORE-ACCT-001" for o in protected_orders)

