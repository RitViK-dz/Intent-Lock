"""Integration tests for the Intents and Approval API endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import init_db
from app.config import settings
from app.crypto import load_or_create_keypair
from app.verifier import CheckoutRequest, verify_checkout, ReasonCode

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path, monkeypatch):
    """Ensure each test runs against a clean isolated temporary database and keys directory."""
    test_db = tmp_path / "test_api.db"
    init_db(test_db)
    test_keys = tmp_path / "keys"

    orig_db = settings.db_path
    orig_keys = settings.keys_dir
    object.__setattr__(settings, "db_path", test_db)
    object.__setattr__(settings, "keys_dir", test_keys)
    yield
    object.__setattr__(settings, "db_path", orig_db)
    object.__setattr__(settings, "keys_dir", orig_keys)


def _valid_intent_payload(**overrides) -> dict:
    base = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "STORE-ACCT-001",
        "summary": "Agent proposing purchase of 14-inch laptop for user",
    }
    base.update(overrides)
    return base


def test_create_intent_success():
    """Verify POST /api/intents creates a pending intent and returns intent_id and status."""
    payload = _valid_intent_payload()
    response = client.post("/api/intents", json=payload)

    assert response.status_code in (200, 201)
    data = response.json()
    assert "intent_id" in data
    assert data["status"] == "pending"


@pytest.mark.parametrize(
    "invalid_payload",
    [
        {"agent_id": ""},  # missing required fields
        _valid_intent_payload(amount_cents=0),  # amount must be > 0
        _valid_intent_payload(amount_cents=-100),  # negative amount
        _valid_intent_payload(amount_cents=45.50),  # float is forbidden
        _valid_intent_payload(item=""),  # empty item
        _valid_intent_payload(payee_id=""),  # empty payee
    ],
)
def test_create_intent_invalid_body_returns_422(invalid_payload):
    """Verify invalid payloads fail Pydantic validation with HTTP 422."""
    response = client.post("/api/intents", json=invalid_payload)
    assert response.status_code == 422


def test_list_intents_pending():
    """Verify GET /api/intents?status=pending lists only pending intents."""
    # Create two intents
    res1 = client.post("/api/intents", json=_valid_intent_payload(item="item-1"))
    res2 = client.post("/api/intents", json=_valid_intent_payload(item="item-2"))
    id1 = res1.json()["intent_id"]
    id2 = res2.json()["intent_id"]

    # Reject one of them
    client.post(f"/api/intents/{id2}/reject")

    # Query pending
    response = client.get("/api/intents?status=pending")
    assert response.status_code == 200
    intents_list = response.json()

    pending_ids = [i["id"] for i in intents_list]
    assert id1 in pending_ids
    assert id2 not in pending_ids


def test_get_intent_by_id_and_404():
    """Verify GET /api/intents/{id} returns details or 404 for nonexistent id."""
    res = client.post("/api/intents", json=_valid_intent_payload())
    intent_id = res.json()["intent_id"]

    # Existing intent
    get_res = client.get(f"/api/intents/{intent_id}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == intent_id
    assert get_res.json()["amount_cents"] == 45000

    # Nonexistent intent
    not_found_res = client.get("/api/intents/nonexistent-id-999")
    assert not_found_res.status_code == 404


def test_create_approve_and_verify_token():
    """Verify full approval cycle: create -> approve -> token passes verify_checkout."""
    create_res = client.post("/api/intents", json=_valid_intent_payload())
    intent_id = create_res.json()["intent_id"]

    # Approve intent
    approve_res = client.post(f"/api/intents/{intent_id}/approve")
    assert approve_res.status_code == 200
    approval_data = approve_res.json()

    assert "token" in approval_data
    assert "expires_at" in approval_data
    token = approval_data["token"]

    # Load public key to verify token
    _, pub_key = load_or_create_keypair(settings.keys_dir)

    req = CheckoutRequest(
        agent_id="shopper-agent-1",
        merchant_id="demo-store",
        item="laptop-14in",
        amount_cents=45000,
        payee_id="STORE-ACCT-001",
    )

    # Token must pass verifier
    result = verify_checkout(
        token=token,
        request=req,
        public_key=pub_key,
        store_id="demo-store",
        db_path=settings.db_path,
    )
    assert result.allowed is True
    assert result.reason == ReasonCode.APPROVED


def test_approving_twice_returns_409():
    """Verify that approving an already approved intent returns 409 Conflict."""
    create_res = client.post("/api/intents", json=_valid_intent_payload())
    intent_id = create_res.json()["intent_id"]

    # First approval succeeds
    first_res = client.post(f"/api/intents/{intent_id}/approve")
    assert first_res.status_code == 200

    # Second approval fails with 409
    second_res = client.post(f"/api/intents/{intent_id}/approve")
    assert second_res.status_code == 409


def test_reject_then_approve_returns_409():
    """Verify that attempting to approve a rejected intent returns 409 Conflict."""
    create_res = client.post("/api/intents", json=_valid_intent_payload())
    intent_id = create_res.json()["intent_id"]

    # Reject intent
    reject_res = client.post(f"/api/intents/{intent_id}/reject")
    assert reject_res.status_code == 200

    # Attempt to approve rejected intent
    approve_res = client.post(f"/api/intents/{intent_id}/approve")
    assert approve_res.status_code == 409


def test_unknown_id_approve_and_reject_returns_404():
    """Verify approving or rejecting an unknown intent ID returns 404."""
    assert client.post("/api/intents/missing-id/approve").status_code == 404
    assert client.post("/api/intents/missing-id/reject").status_code == 404


def test_public_key_endpoint_returns_pem():
    """Verify GET /api/public-key returns PEM text with standard delimiters."""
    response = client.get("/api/public-key")
    assert response.status_code == 200
    content = response.text
    assert "-----BEGIN PUBLIC KEY-----" in content
    assert "-----END PUBLIC KEY-----" in content
