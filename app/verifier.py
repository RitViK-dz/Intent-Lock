"""IntentLock token verification engine.

The heart of the project: validates cryptographic human approval tokens presented
at store checkout.

Security Architecture:
1. Public Key Only: Verifies signatures using only the issuer's public key; never possesses private key.
2. Strict Check Ordering: Cryptographic signature is verified BEFORE parsing any payload fields.
3. Atomic Nonce Consumption as the Final Step: Protects legitimate tokens from being burned if earlier
   checks fail, while atomically thwarting replay and concurrent race attacks.
4. Token Privacy: Writes comprehensive audit logs for all attempts without ever recording the token itself.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import time
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.crypto import verify
from app.tokens import parse_token, decode_payload, TokenFormatError
from app.db import consume_nonce, log_event


class ReasonCode(str, Enum):
    """Reason codes returned by the verifier indicating the exact check outcome."""

    APPROVED = "APPROVED"
    MISSING_TOKEN = "MISSING_TOKEN"
    MALFORMED_TOKEN = "MALFORMED_TOKEN"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    MERCHANT_MISMATCH = "MERCHANT_MISMATCH"
    AGENT_MISMATCH = "AGENT_MISMATCH"
    ITEM_MISMATCH = "ITEM_MISMATCH"
    PAYEE_MISMATCH = "PAYEE_MISMATCH"
    AMOUNT_EXCEEDS_LIMIT = "AMOUNT_EXCEEDS_LIMIT"
    TOKEN_REPLAYED = "TOKEN_REPLAYED"


@dataclass
class CheckoutRequest:
    """Store checkout parameters submitted by the agent.

    Money rule: amount_cents is stored strictly as integer cents (never floats).
    """

    agent_id: str
    merchant_id: str
    item: str
    amount_cents: int
    payee_id: str


@dataclass
class VerifyResult:
    """Result returned by verify_checkout to the store router."""

    allowed: bool
    reason: ReasonCode
    nonce: str | None
    elapsed_ms: float


def verify_checkout(
    token: str | None,
    request: CheckoutRequest,
    public_key: ed25519.Ed25519PublicKey,
    store_id: str,
    now: int | float | None = None,
    skew_seconds: int = 5,
    db_path: Path | str | None = None,
) -> VerifyResult:
    """Verify an approval token against an incoming store checkout request.

    Stops at the first failing check according to the strict verification pipeline.
    """
    start_time = time.perf_counter()
    current_time = int(now if now is not None else time.time())
    extracted_nonce: str | None = None

    def _finish(allowed: bool, reason: ReasonCode, nonce_val: str | None) -> VerifyResult:
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Security: Record every authorization decision to the immutable audit log
        # RULE: Never log the raw token or secret values in the audit trail
        event_name = "checkout_allowed" if allowed else "checkout_blocked"
        audit_detail: dict[str, Any] = {
            "reason": reason.value,
            "merchant_id": request.merchant_id,
            "store_id": store_id,
            "item": request.item,
            "amount_cents": request.amount_cents,
            "payee_id": request.payee_id,
            "nonce": nonce_val,
        }
        log_event(
            event=event_name,
            actor=request.agent_id,
            intent_id=None,
            detail=audit_detail,
            db_path=db_path,
            now=current_time,
        )

        return VerifyResult(
            allowed=allowed,
            reason=reason,
            nonce=nonce_val,
            elapsed_ms=elapsed_ms,
        )

    # Step 0: Ensure token string was supplied
    if not token or not isinstance(token, str) or not token.strip():
        return _finish(False, ReasonCode.MISSING_TOKEN, None)

    # Step 1: Parse token into exact (payload_bytes, signature_bytes)
    # Does NOT parse payload JSON; only validates base64 and 2-part structure
    try:
        payload_bytes, signature_bytes = parse_token(token)
    except TokenFormatError:
        return _finish(False, ReasonCode.MALFORMED_TOKEN, None)

    # Step 2: Validate Ed25519 digital signature BEFORE reading any payload field
    # Security: If signature check fails, payload is untrusted and must never be interpreted
    if not verify(public_key, signature_bytes, payload_bytes):
        return _finish(False, ReasonCode.BAD_SIGNATURE, None)

    # Step 3: Decode JSON payload ONLY after signature authenticity is proven
    try:
        payload = decode_payload(payload_bytes)
    except Exception:
        return _finish(False, ReasonCode.MALFORMED_TOKEN, None)

    extracted_nonce = payload.get("nonce")

    # Step 4: Expiration check with clock skew tolerance
    # Security: Small clock skew prevents false rejections due to minor NTP clock offset
    exp = payload.get("exp")
    if exp is None or not isinstance(exp, (int, float)) or current_time > int(exp) + skew_seconds:
        return _finish(False, ReasonCode.TOKEN_EXPIRED, extracted_nonce)

    # Step 5: Merchant matching
    # Security: Token must be approved specifically for this store AND match request merchant
    token_merchant = payload.get("merchant_id")
    if token_merchant != store_id or token_merchant != request.merchant_id:
        return _finish(False, ReasonCode.MERCHANT_MISMATCH, extracted_nonce)

    # Step 6: Agent identity matching
    # Security: Prevents token theft across agents; only designated agent may present token
    if payload.get("agent_id") != request.agent_id:
        return _finish(False, ReasonCode.AGENT_MISMATCH, extracted_nonce)

    # Step 7: Item matching
    # Security: Prevents hijacked agent from swapping authorized item for another product
    if payload.get("item") != request.item:
        return _finish(False, ReasonCode.ITEM_MISMATCH, extracted_nonce)

    # Step 8: Payee account matching (primary prompt injection vector)
    # Security: Prevents hijacked agent from diverting payment to attacker's bank account
    if payload.get("payee_id") != request.payee_id:
       return _finish(False, ReasonCode.PAYEE_MISMATCH, extracted_nonce)

    # Step 9: Amount ceiling check
    # Security: Request amount must not exceed user-approved max ceiling; stored as integer cents
    max_cents = payload.get("max_amount_cents")
    if (
        max_cents is None
        or not isinstance(request.amount_cents, int)
        or not isinstance(max_cents, int)
        or request.amount_cents > max_cents
    ):
        return _finish(False, ReasonCode.AMOUNT_EXCEEDS_LIMIT, extracted_nonce)

    # Step 10: Consume one-time nonce atomically as the LAST step
    # Security:
    # 1. Placed last so rejected requests do not consume or burn a valid token.
    # 2. Executed atomically at the DB constraint layer so concurrent requests cannot replay it.
    if not extracted_nonce or not consume_nonce(
        extracted_nonce, merchant_id=store_id, db_path=db_path, now=current_time
    ):
        return _finish(False, ReasonCode.TOKEN_REPLAYED, extracted_nonce)

    # Step 11: All checks passed -> APPROVED
    return _finish(True, ReasonCode.APPROVED, extracted_nonce)
