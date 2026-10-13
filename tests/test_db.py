"""Tests for SQLite database storage, atomic nonce consumption, and audit logging."""

import concurrent.futures
from pathlib import Path
import pytest

from app.db import (
    init_db,
    create_intent,
    get_intent,
    list_intents,
    set_intent_status,
    consume_nonce,
    log_event,
    list_audit,
)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Fixture providing a freshly initialized SQLite database in a temporary directory."""
    database_file = tmp_path / "test_intentlock.db"
    init_db(database_file)
    return database_file


def test_create_and_get_intent(db_path: Path):
    """Verify intent creation and retrieval with exact fields."""
    intent = create_intent(
        intent_id="intent-101",
        agent_id="shopper-agent-1",
        merchant_id="demo-store",
        item="laptop-14in",
        amount_cents=45000,
        payee_id="STORE-ACCT-001",
        summary="User requested purchasing 14-inch laptop",
        db_path=db_path,
        now=1700000000,
    )

    assert intent["id"] == "intent-101"
    assert intent["status"] == "pending"
    assert intent["amount_cents"] == 45000
    assert intent["created_at"] == 1700000000
    assert intent["decided_at"] is None

    retrieved = get_intent("intent-101", db_path=db_path)
    assert retrieved is not None
    assert retrieved["id"] == "intent-101"
    assert retrieved["payee_id"] == "STORE-ACCT-001"
    assert retrieved["status"] == "pending"


def test_list_intents_filtering(db_path: Path):
    """Verify list_intents returns all intents and filters by status."""
    create_intent(
        intent_id="i1",
        agent_id="a1",
        merchant_id="m1",
        item="item1",
        amount_cents=1000,
        payee_id="p1",
        summary="sum1",
        db_path=db_path,
        now=100,
    )
    create_intent(
        intent_id="i2",
        agent_id="a1",
        merchant_id="m1",
        item="item2",
        amount_cents=2000,
        payee_id="p1",
        summary="sum2",
        db_path=db_path,
        now=200,
    )

    set_intent_status("i2", "approved", db_path=db_path, decided_at=250)

    # All intents
    all_intents = list_intents(db_path=db_path)
    assert len(all_intents) == 2

    # Filtered by pending
    pending_intents = list_intents(status="pending", db_path=db_path)
    assert len(pending_intents) == 1
    assert pending_intents[0]["id"] == "i1"

    # Filtered by approved
    approved_intents = list_intents(status="approved", db_path=db_path)
    assert len(approved_intents) == 1
    assert approved_intents[0]["id"] == "i2"


def test_intent_status_transitions(db_path: Path):
    """Verify intent status transitions from pending to approved and rejected."""
    create_intent(
        intent_id="tx-1",
        agent_id="a1",
        merchant_id="m1",
        item="phone",
        amount_cents=80000,
        payee_id="store",
        summary="Buy phone",
        db_path=db_path,
        now=1000,
    )

    # Approve
    ok = set_intent_status("tx-1", "approved", db_path=db_path, decided_at=1050)
    assert ok is True
    intent = get_intent("tx-1", db_path=db_path)
    assert intent["status"] == "approved"
    assert intent["decided_at"] == 1050

    # Reject
    ok = set_intent_status("tx-1", "rejected", db_path=db_path, decided_at=1060)
    assert ok is True
    intent = get_intent("tx-1", db_path=db_path)
    assert intent["status"] == "rejected"
    assert intent["decided_at"] == 1060


def test_consume_nonce_first_and_second_time(db_path: Path):
    """Verify consume_nonce returns True on first call and False on replay."""
    nonce = "0123456789abcdef0123456789abcdef"

    # First call: must succeed (nonce consumed)
    assert consume_nonce(nonce, merchant_id="demo-store", db_path=db_path) is True

    # Replay attack: must fail atomically
    assert consume_nonce(nonce, merchant_id="demo-store", db_path=db_path) is False


def test_consume_nonce_concurrent_20_threads(db_path: Path):
    """Verify atomic race condition: 20 threads racing for the same nonce yields exactly one True."""
    target_nonce = "concurrent_nonce_test_deadbeef001"
    num_threads = 20

    def attempt_consume() -> bool:
        return consume_nonce(target_nonce, merchant_id="demo-store", db_path=db_path)

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(attempt_consume) for _ in range(num_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Exactly one thread must succeed; all others must be rejected
    assert results.count(True) == 1
    assert results.count(False) == num_threads - 1


def test_audit_log_newest_first(db_path: Path):
    """Verify audit entries are persisted and returned in newest-first order."""
    log_event(
        event="INTENT_CREATED",
        actor="shopper-agent-1",
        intent_id="intent-1",
        detail={"item": "book"},
        db_path=db_path,
        now=1000,
    )
    log_event(
        event="INTENT_APPROVED",
        actor="demo-user",
        intent_id="intent-1",
        detail={"approved": True},
        db_path=db_path,
        now=1010,
    )
    log_event(
        event="CHECKOUT_COMPLETED",
        actor="demo-store",
        intent_id="intent-1",
        detail={"order_id": "ord-99"},
        db_path=db_path,
        now=1020,
    )

    logs = list_audit(limit=10, db_path=db_path)
    assert len(logs) == 3

    # Newest entry must be first
    assert logs[0]["event"] == "CHECKOUT_COMPLETED"
    assert logs[0]["detail"]["order_id"] == "ord-99"
    assert logs[1]["event"] == "INTENT_APPROVED"
    assert logs[2]["event"] == "INTENT_CREATED"

    # Test limit parameter
    limited = list_audit(limit=2, db_path=db_path)
    assert len(limited) == 2
    assert limited[0]["event"] == "CHECKOUT_COMPLETED"
