"""Unit and audit compliance tests for the IntentLock verifier engine."""

from pathlib import Path
import pytest

from app.crypto import load_or_create_keypair
from app.tokens import create_token
from app.db import init_db, list_audit
from app.verifier import (
    ReasonCode,
    CheckoutRequest,
    verify_checkout,
)


@pytest.fixture
def verifier_setup(tmp_path: Path):
    """Fixture providing store configuration, keys, and an isolated SQLite db."""
    db_file = tmp_path / "unit_verifier.db"
    init_db(db_file)

    keys_dir = tmp_path / "keys"
    priv_key, pub_key = load_or_create_keypair(keys_dir)

    return {
        "db_path": db_file,
        "priv_key": priv_key,
        "pub_key": pub_key,
        "store_id": "demo-store",
    }


def test_audit_log_written_for_allowed_and_blocked(verifier_setup):
    """Verify every checkout verification logs an audit entry, but NEVER the raw token."""
    db_path = verifier_setup["db_path"]
    pub_key = verifier_setup["pub_key"]
    priv_key = verifier_setup["priv_key"]
    store_id = verifier_setup["store_id"]

    token = create_token(
        priv_key,
        user_id="user-1",
        agent_id="agent-1",
        merchant_id=store_id,
        action="purchase",
        item="mouse",
        max_amount_cents=2500,
        currency="USD",
        payee_id="STORE-ACCT-001",
        ttl_seconds=300,
        now=1000,
    )

    valid_req = CheckoutRequest(
        agent_id="agent-1",
        merchant_id=store_id,
        item="mouse",
        amount_cents=2500,
        payee_id="STORE-ACCT-001",
    )

    # 1. Allowed verification
    res_ok = verify_checkout(
        token=token,
        request=valid_req,
        public_key=pub_key,
        store_id=store_id,
        now=1050,
        db_path=db_path,
    )
    assert res_ok.allowed is True

    # 2. Blocked verification (tampered amount)
    tampered_req = CheckoutRequest(
        agent_id="agent-1",
        merchant_id=store_id,
        item="mouse",
        amount_cents=99999,
        payee_id="STORE-ACCT-001",
    )
    res_blocked = verify_checkout(
        token=token,
        request=tampered_req,
        public_key=pub_key,
        store_id=store_id,
        now=1060,
        db_path=db_path,
    )
    assert res_blocked.allowed is False

    # Check audit logs (newest first)
    logs = list_audit(limit=10, db_path=db_path)
    assert len(logs) == 2

    # Most recent is blocked event
    blocked_event = logs[0]
    assert blocked_event["event"] == "checkout_blocked"
    assert blocked_event["detail"]["reason"] == ReasonCode.AMOUNT_EXCEEDS_LIMIT.value
    assert blocked_event["actor"] == "agent-1"

    # Previous is allowed event
    allowed_event = logs[1]
    assert allowed_event["event"] == "checkout_allowed"
    assert allowed_event["detail"]["reason"] == ReasonCode.APPROVED.value

    # CRITICAL SECURITY RULE: Confirm raw token is NEVER logged in audit trail
    for entry in logs:
        assert "token" not in entry["detail"]
        assert token not in str(entry)


def test_verifier_requires_only_public_key(verifier_setup):
    """Verify that verifier executes with only the Ed25519 public key and no private key."""
    pub_key = verifier_setup["pub_key"]
    token = create_token(
        verifier_setup["priv_key"],
        user_id="user-1",
        agent_id="agent-1",
        merchant_id="demo-store",
        action="purchase",
        item="keyboard",
        max_amount_cents=5000,
        currency="USD",
        payee_id="STORE-ACCT-001",
        ttl_seconds=300,
        now=1000,
    )
    req = CheckoutRequest(
        agent_id="agent-1",
        merchant_id="demo-store",
        item="keyboard",
        amount_cents=5000,
        payee_id="STORE-ACCT-001",
    )

    # Calling with public_key only
    result = verify_checkout(
        token=token,
        request=req,
        public_key=pub_key,
        store_id="demo-store",
        now=1050,
        db_path=verifier_setup["db_path"],
    )
    assert result.allowed is True
    assert result.reason == ReasonCode.APPROVED


def test_stop_at_first_failure_order(verifier_setup):
    """Verify that verifier halts on the earliest invalid check in sequence."""
    pub_key = verifier_setup["pub_key"]
    req = CheckoutRequest(
        agent_id="agent-1",
        merchant_id="demo-store",
        item="keyboard",
        amount_cents=5000,
        payee_id="STORE-ACCT-001",
    )

    # A malformed token should fail with MALFORMED_TOKEN before attempting signature or expiry checks
    res = verify_checkout(
        token="invalid.base64@@@.stuff",
        request=req,
        public_key=pub_key,
        store_id="demo-store",
        now=1050,
        db_path=verifier_setup["db_path"],
    )
    assert res.reason == ReasonCode.MALFORMED_TOKEN
