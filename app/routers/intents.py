"""API router for intent proposal, dashboard listing, approval, and rejection.

Also exposes the issuer public key endpoint so stores can verify tokens without secrets.
"""

import time
import uuid
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import PlainTextResponse

from app.config import settings
from app.crypto import load_or_create_keypair, public_key_to_pem
from app.db import (
    init_db,
    create_intent,
    get_intent,
    list_intents,
    set_intent_status,
    log_event,
)
from app.tokens import create_token
from app.models import (
    CreateIntentRequest,
    CreateIntentResponse,
    IntentResponse,
    ApproveIntentResponse,
    RejectIntentResponse,
)

router = APIRouter(tags=["intents"])


def _ensure_db_and_keys():
    """Ensure database schema and keypair are initialized."""
    init_db(settings.db_path)
    return load_or_create_keypair(settings.keys_dir)


@router.post(
    "/api/intents",
    response_model=CreateIntentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose an agent action for human review",
)
def propose_intent(req: CreateIntentRequest) -> CreateIntentResponse:
    """Agent endpoint: Submit a proposed purchase action creating a pending intent."""
    _ensure_db_and_keys()

    intent_id = f"intent-{uuid.uuid4().hex[:12]}"

    created = create_intent(
        intent_id=intent_id,
        agent_id=req.agent_id,
        merchant_id=req.merchant_id,
        item=req.item,
        amount_cents=req.amount_cents,
        payee_id=req.payee_id,
        summary=req.summary,
        db_path=settings.db_path,
    )

    # Security: Audit trail logs proposed action without sensitive credentials
    log_event(
        event="intent_created",
        actor=req.agent_id,
        intent_id=intent_id,
        detail={
            "merchant_id": req.merchant_id,
            "item": req.item,
            "amount_cents": req.amount_cents,
            "payee_id": req.payee_id,
            "summary": req.summary,
        },
        db_path=settings.db_path,
    )

    return CreateIntentResponse(
        intent_id=created["id"],
        status=created["status"],
    )


@router.get(
    "/api/intents",
    response_model=list[IntentResponse],
    summary="List intents for human approval dashboard",
)
def get_intents(
    status: str | None = Query(None, description="Filter intents by status (e.g. pending)")
) -> list[IntentResponse]:
    """Dashboard endpoint: Query intents, optionally filtered by status."""
    _ensure_db_and_keys()
    records = list_intents(status=status, db_path=settings.db_path)
    return [IntentResponse(**rec) for rec in records]


@router.get(
    "/api/intents/{intent_id}",
    response_model=IntentResponse,
    summary="Fetch full details for an intent",
)
def get_intent_details(intent_id: str) -> IntentResponse:
    """Fetch single intent by ID or return 404."""
    _ensure_db_and_keys()
    intent = get_intent(intent_id, db_path=settings.db_path)
    if not intent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Intent '{intent_id}' not found",
        )
    return IntentResponse(**intent)


@router.post(
    "/api/intents/{intent_id}/approve",
    response_model=ApproveIntentResponse,
    summary="Human approval: mints single-use cryptographic authorization token",
)
def approve_intent(intent_id: str) -> ApproveIntentResponse:
    """Human approval endpoint.

    PROTOTYPE LIMITATION: the dashboard has no login. Production needs an authenticated user,
    confirmation on a separate trusted device or channel, and rate limiting, so that the agent
    can never approve its own request.
    """
    priv_key, _ = _ensure_db_and_keys()

    intent = get_intent(intent_id, db_path=settings.db_path)
    if not intent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Intent '{intent_id}' not found",
        )

    # Security: Only pending intents can be approved. Tokens are issued strictly ONCE.
    if intent["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot approve intent with status '{intent['status']}'",
        )

    now = int(time.time())
    expires_at = now + settings.token_ttl_seconds

    # Security: Cryptographically bind the token to the EXACT parameters recorded in the approved intent
    token = create_token(
        private_key=priv_key,
        user_id="demo-user",
        agent_id=intent["agent_id"],
        merchant_id=intent["merchant_id"],
        action="purchase",
        item=intent["item"],
        max_amount_cents=intent["amount_cents"],
        currency="USD",
        payee_id=intent["payee_id"],
        ttl_seconds=settings.token_ttl_seconds,
        now=now,
    )

    # Transition state to approved
    set_intent_status(intent_id, "approved", db_path=settings.db_path, decided_at=now)

    # Security: Record approval in audit log. RULE: Never log the raw token itself!
    log_event(
        event="intent_approved",
        actor="demo-user",
        intent_id=intent_id,
        detail={
            "status": "approved",
            "expires_at": expires_at,
            "token_minted": True,
        },
        db_path=settings.db_path,
        now=now,
    )

    return ApproveIntentResponse(
        token=token,
        expires_at=expires_at,
    )


@router.post(
    "/api/intents/{intent_id}/reject",
    response_model=RejectIntentResponse,
    summary="Human rejection: rejects the intent",
)
def reject_intent(intent_id: str) -> RejectIntentResponse:
    """Human rejection endpoint."""
    _ensure_db_and_keys()

    intent = get_intent(intent_id, db_path=settings.db_path)
    if not intent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Intent '{intent_id}' not found",
        )

    if intent["status"] != "pending":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot reject intent with status '{intent['status']}'",
        )

    now = int(time.time())
    set_intent_status(intent_id, "rejected", db_path=settings.db_path, decided_at=now)

    # Record rejection in audit log
    log_event(
        event="intent_rejected",
        actor="demo-user",
        intent_id=intent_id,
        detail={"status": "rejected"},
        db_path=settings.db_path,
        now=now,
    )

    return RejectIntentResponse(
        intent_id=intent_id,
        status="rejected",
    )


@router.get(
    "/api/public-key",
    response_class=PlainTextResponse,
    summary="Fetch the issuer public key in PEM format",
)
def get_public_key() -> str:
    """Returns the issuer public key as standard PEM text.

    Store verifiers need ONLY this public key to verify human approval tokens.
    """
    _, pub_key = _ensure_db_and_keys()
    return public_key_to_pem(pub_key)
