"""Integration tests for the Mock Store endpoints (protected & unprotected checkout)."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import init_db
from app.config import settings
from app.crypto import load_or_create_keypair

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path):
    """Ensure each test runs against a clean isolated temporary database and keys directory."""
    test_db = tmp_path / "test_store_api.db"
    init_db(test_db)
    test_keys = tmp_path / "keys"

    orig_db = settings.db_path
    orig_keys = settings.keys_dir
    object.__setattr__(settings, "db_path", test_db)
    object.__setattr__(settings, "keys_dir", test_keys)
    yield
    object.__setattr__(settings, "db_path", orig_db)
    object.__setattr__(settings, "keys_dir", orig_keys)


def _create_and_approve_intent(**overrides) -> dict:
    """Helper to propose and approve an intent, returning intent_id and token."""
    payload = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "STORE-ACCT-001",
        "summary": "Propose buying laptop",
    }
    payload.update(overrides)

    create_res = client.post("/api/intents", json=payload)
    intent_id = create_res.json()["intent_id"]

    approve_res = client.post(f"/api/intents/{intent_id}/approve")
    token = approve_res.json()["token"]

    return {"intent_id": intent_id, "token": token, "payload": payload}


def test_get_catalog():
    """Verify GET /store/catalog returns the fixed catalog with correct prices and payee."""
    response = client.get("/store/catalog")
    assert response.status_code == 200
    items = response.json()

    assert len(items) == 3
    items_by_id = {item["id"]: item for item in items}

    assert "laptop-14in" in items_by_id
    assert items_by_id["laptop-14in"]["price_cents"] == 45000
    assert items_by_id["laptop-14in"]["payee_id"] == "STORE-ACCT-001"

    assert "headphones" in items_by_id
    assert items_by_id["headphones"]["price_cents"] == 8000
    assert items_by_id["headphones"]["payee_id"] == "STORE-ACCT-001"

    assert "usb-hub" in items_by_id
    assert items_by_id["usb-hub"]["price_cents"] == 2500
    assert items_by_id["usb-hub"]["payee_id"] == "STORE-ACCT-001"


def test_legitimate_protected_checkout_flow():
    """Verify full end-to-end flow: intent -> approve -> protected checkout succeeds."""
    approved = _create_and_approve_intent()
    token = approved["token"]

    checkout_payload = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "STORE-ACCT-001",
        "token": token,
    }

    response = client.post("/store/checkout", json=checkout_payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "approved"
    assert data["reason"] == "APPROVED"
    assert "order_id" in data
    assert data["order_id"].startswith("order-")


@pytest.mark.parametrize(
    "tamper_field,tamper_val,expected_reason",
    [
        ("payee_id", "ATTACKER-EVIL-007", "PAYEE_MISMATCH"),
        ("item", "gift-card-500", "ITEM_MISMATCH"),
        ("amount_cents", 45001, "AMOUNT_EXCEEDS_LIMIT"),
        ("merchant_id", "evil-store", "MERCHANT_MISMATCH"),
        ("agent_id", "evil-agent", "AGENT_MISMATCH"),
    ],
)
def test_blocked_reasons_return_http_403(tamper_field, tamper_val, expected_reason):
    """Verify each validation failure returns HTTP 403 with exact reason code."""
    approved = _create_and_approve_intent()
    token = approved["token"]

    checkout_payload = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "STORE-ACCT-001",
        "token": token,
    }
    checkout_payload[tamper_field] = tamper_val

    response = client.post("/store/checkout", json=checkout_payload)
    assert response.status_code == 403
    data = response.json()
    assert data["status"] == "blocked"
    assert data["reason"] == expected_reason


def test_missing_token_returns_403():
    """Verify checkout without a token returns HTTP 403 MISSING_TOKEN."""
    checkout_payload = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "STORE-ACCT-001",
    }
    response = client.post("/store/checkout", json=checkout_payload)
    assert response.status_code == 403
    assert response.json()["reason"] == "MISSING_TOKEN"


def test_replayed_token_returns_403():
    """Verify that replaying a token at protected checkout returns HTTP 403 TOKEN_REPLAYED."""
    approved = _create_and_approve_intent()
    token = approved["token"]

    checkout_payload = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "STORE-ACCT-001",
        "token": token,
    }

    # First attempt: succeeds
    res1 = client.post("/store/checkout", json=checkout_payload)
    assert res1.status_code == 200

    # Second attempt (replay): blocked
    res2 = client.post("/store/checkout", json=checkout_payload)
    assert res2.status_code == 403
    assert res2.json()["reason"] == "TOKEN_REPLAYED"


def test_hijacked_request_unprotected_vs_protected_divergence():
    """The Attack Demo: Unprotected checkout allows payment diversion; IntentLock blocks it."""
    hijacked_payload = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "ATTACKER-ACCOUNT-666",  # payment diverted!
    }

    # 1. Unprotected endpoint: accepts hijacked purchase without verification
    unprotected_res = client.post("/store/checkout-unprotected", json=hijacked_payload)
    assert unprotected_res.status_code == 200
    unprotected_data = unprotected_res.json()
    assert unprotected_data["status"] == "completed_UNPROTECTED"
    assert "order_id" in unprotected_data

    # 2. Protected endpoint with token matching genuine payee STORE-ACCT-001:
    approved = _create_and_approve_intent(payee_id="STORE-ACCT-001")
    hijacked_payload_with_token = dict(hijacked_payload)
    hijacked_payload_with_token["token"] = approved["token"]

    protected_res = client.post("/store/checkout", json=hijacked_payload_with_token)
    assert protected_res.status_code == 403
    assert protected_res.json()["reason"] == "PAYEE_MISMATCH"


def test_get_orders_shows_endpoints_and_payees():
    """Verify GET /store/orders lists completed orders and shows destination payees."""
    # Run one unprotected order (diverted)
    client.post(
        "/store/checkout-unprotected",
        json={
            "agent_id": "agent-1",
            "merchant_id": "demo-store",
            "item": "usb-hub",
            "amount_cents": 2500,
            "payee_id": "ATTACKER-SWAP-ACCT",
        },
    )

    # Run one protected order (legitimate)
    approved = _create_and_approve_intent(item="usb-hub", amount_cents=2500, payee_id="STORE-ACCT-001")
    client.post(
        "/store/checkout",
        json={
            "agent_id": "shopper-agent-1",
            "merchant_id": "demo-store",
            "item": "usb-hub",
            "amount_cents": 2500,
            "payee_id": "STORE-ACCT-001",
            "token": approved["token"],
        },
    )

    response = client.get("/store/orders")
    assert response.status_code == 200
    orders = response.json()
    assert len(orders) == 2

    endpoints = [o["endpoint"] for o in orders]
    assert "unprotected" in endpoints
    assert "protected" in endpoints

    payees = [o["payee_id"] for o in orders]
    assert "ATTACKER-SWAP-ACCT" in payees
    assert "STORE-ACCT-001" in payees
