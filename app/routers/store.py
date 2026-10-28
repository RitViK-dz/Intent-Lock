"""Mock Store API Router: Catalog, Protected Checkout, Unprotected Checkout, and Orders.

Demonstrates the attack versus protected checkout difference:
- /store/checkout enforces cryptographic IntentLock token validation using only the public key.
- /store/checkout-unprotected demonstrates vulnerable baseline behavior without verification.
"""

from pathlib import Path
import uuid
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.config import settings
from app.crypto import load_or_create_keypair
from app.db import init_db, create_order, list_orders
from app.verifier import CheckoutRequest, verify_checkout, ReasonCode
from app.models import (
    CatalogItem,
    StoreCheckoutRequest,
    StoreCheckoutResponse,
    OrderResponse,
)

router = APIRouter(prefix="/store", tags=["store"])

# Fixed store catalog
CATALOG: list[dict] = [
    {
        "id": "laptop-14in",
        "name": "14-inch Laptop",
        "price_cents": 45000,
        "currency": "USD",
        "payee_id": "STORE-ACCT-001",
    },
    {
        "id": "headphones",
        "name": "Wireless Noise-Canceling Headphones",
        "price_cents": 8000,
        "currency": "USD",
        "payee_id": "STORE-ACCT-001",
    },
    {
        "id": "usb-hub",
        "name": "USB-C Multi-Port Hub",
        "price_cents": 2500,
        "currency": "USD",
        "payee_id": "STORE-ACCT-001",
    },
]


def _get_store_public_key():
    """Security Invariant: The verifier loads and uses ONLY the issuer public key.

    The store has no access to the issuer private key.
    """
    init_db(settings.db_path)
    _, pub_key = load_or_create_keypair(settings.keys_dir)
    return pub_key


@router.get(
    "/catalog",
    response_model=list[CatalogItem],
    summary="Get merchant product catalog",
)
def get_catalog() -> list[CatalogItem]:
    """Return the fixed product catalog with authentic payee STORE-ACCT-001."""
    return [CatalogItem(**item) for item in CATALOG]


@router.post(
    "/checkout",
    response_model=StoreCheckoutResponse,
    summary="Protected checkout requiring valid IntentLock token",
)
def protected_checkout(req: StoreCheckoutRequest):
    """Protected checkout endpoint.

    Validates the cryptographic human approval token before executing the order.
    Returns HTTP 200 on approval, or HTTP 403 with specific ReasonCode if blocked.
    """
    pub_key = _get_store_public_key()

    # Formulate typed request for verifier engine
    verifier_req = CheckoutRequest(
        agent_id=req.agent_id,
        merchant_id=req.merchant_id,
        item=req.item,
        amount_cents=req.amount_cents,
        payee_id=req.payee_id,
        agent_proof=req.agent_proof,
    )

    # Security: Verify token against request parameters using public key only
    result = verify_checkout(
        token=req.token,
        request=verifier_req,
        public_key=pub_key,
        store_id=settings.store_id,
        db_path=settings.db_path,
    )

    if not result.allowed:
        # Security: Return HTTP 403 Forbidden with exact reason code
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "status": "blocked",
                "reason": result.reason.value,
            },
        )

    # All checks passed & nonce atomically consumed -> Create completed order
    order_id = f"order-{uuid.uuid4().hex[:12]}"
    create_order(
        order_id=order_id,
        agent_id=req.agent_id,
        merchant_id=req.merchant_id,
        item=req.item,
        amount_cents=req.amount_cents,
        payee_id=req.payee_id,
        endpoint="protected",
        db_path=settings.db_path,
    )

    return StoreCheckoutResponse(
        status="approved",
        order_id=order_id,
        reason=ReasonCode.APPROVED.value,
    )


@router.post(
    "/checkout-unprotected",
    response_model=StoreCheckoutResponse,
    summary="Unprotected checkout for demo comparison (shows vulnerability)",
)
def unprotected_checkout(req: StoreCheckoutRequest):
    """VULNERABLE BASELINE ENDPOINT (DEMO-ONLY).

    PROMINENT WARNING:
    This endpoint exists strictly for the hackathon demonstration to show the 'before' state.
    It performs ZERO token verification and blindly executes whatever checkout request
    the AI agent submits. In an attack scenario, prompt injection causes the agent to divert
    funds to an attacker's payee account, which this unprotected endpoint blindly completes.
    """
    init_db(settings.db_path)
    order_id = f"order-unprot-{uuid.uuid4().hex[:10]}"

    # Unconditionally complete order, recording whatever payee was submitted
    create_order(
        order_id=order_id,
        agent_id=req.agent_id,
        merchant_id=req.merchant_id,
        item=req.item,
        amount_cents=req.amount_cents,
        payee_id=req.payee_id,
        endpoint="unprotected",
        db_path=settings.db_path,
    )

    return StoreCheckoutResponse(
        status="completed_UNPROTECTED",
        order_id=order_id,
        warning="demo-only endpoint that shows the risk without IntentLock",
    )


@router.get(
    "/orders",
    response_model=list[OrderResponse],
    summary="List completed store orders",
)
def get_orders(limit: int = 50) -> list[OrderResponse]:
    """List completed orders to inspect which endpoint processed them and which payee received funds."""
    init_db(settings.db_path)
    records = list_orders(limit=limit, db_path=settings.db_path)
    return [OrderResponse(**rec) for rec in records]
