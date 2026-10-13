"""Intent authorization token creation, serialization, and parsing.

Token format: base64url(payload_json) + "." + base64url(ed25519_signature)
The signature is created directly over the exact serialized payload JSON bytes,
which completely eliminates subtle JSON canonicalization vulnerabilities.
"""

import base64
import binascii
import json
import secrets
import time
from typing import Any
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.crypto import sign


class TokenFormatError(ValueError):
    """Raised when a token string cannot be split or base64-decoded."""


def b64url_encode(data: bytes) -> str:
    """Encode bytes using URL-safe base64 without '=' padding.

    Omitting padding characters makes tokens safe to transport in headers, query params, or URLs.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    """Decode a URL-safe unpadded base64 string back into bytes.

    Restores required '=' padding before invoking standard base64 decoding.
    """
    if not isinstance(s, str):
        raise TokenFormatError("Token part must be a string")

    # Base64 strings must have length divisible by 4; restore stripped padding
    rem = len(s) % 4
    if rem > 0:
        s += "=" * (4 - rem)

    try:
        return base64.urlsafe_b64decode(s.encode("ascii"))
    except (binascii.Error, UnicodeError, ValueError) as exc:
        raise TokenFormatError(f"Invalid base64 encoding: {exc}") from exc


def create_token(
    private_key: ed25519.Ed25519PrivateKey,
    *,
    user_id: str,
    agent_id: str,
    merchant_id: str,
    action: str,
    item: str,
    max_amount_cents: int,
    currency: str,
    payee_id: str,
    ttl_seconds: int,
    now: int | float | None = None,
) -> str:
    """Issue a cryptographically signed human approval token bound to exact action parameters.

    Security Rules Enforced:
    1. Monetary spending limits are stored strictly as integer cents (never floats).
    2. Nonce is 16 cryptographically secure random bytes (32 hex characters).
    3. Expiry is enforced relative to issuance time.
    4. Signature covers exact raw JSON bytes.
    """
    # Security: Enforce integer representation for money to prevent floating-point rounding attacks
    if not isinstance(max_amount_cents, int):
        raise TypeError("max_amount_cents must be an integer (cents)")

    # Security: Generate high-entropy 128-bit (16-byte) random nonce for single-use guarantee
    nonce = secrets.token_hex(16)

    # Security: Compute deterministic integer timestamps
    iat = int(now if now is not None else time.time())
    exp = iat + int(ttl_seconds)

    payload: dict[str, Any] = {
        "v": 1,
        "nonce": nonce,
        "user_id": user_id,
        "agent_id": agent_id,
        "merchant_id": merchant_id,
        "action": action,
        "item": item,
        "max_amount_cents": max_amount_cents,
        "currency": currency,
        "payee_id": payee_id,
        "iat": iat,
        "exp": exp,
    }

    # Security: Serialize with deterministic compact separators (no whitespace ambiguity)
    payload_json_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    # Security: Sign exact bytes directly so signature is immune to JSON key ordering changes
    signature = sign(private_key, payload_json_bytes)

    # Assemble compact token: base64url(payload) + "." + base64url(signature)
    return f"{b64url_encode(payload_json_bytes)}.{b64url_encode(signature)}"


def parse_token(token: str) -> tuple[bytes, bytes]:
    """Parse a token into its raw (payload_bytes, signature_bytes) components.

    Security Rule: This function MUST NOT parse or interpret JSON payload data.
    The verifier must verify the signature bytes against payload bytes BEFORE inspecting payload fields.
    """
    if not isinstance(token, str) or not token:
        raise TokenFormatError("Token must be a non-empty string")

    # Token must have exactly two parts separated by a single dot
    parts = token.split(".")
    if len(parts) != 2:
        raise TokenFormatError(f"Expected 2 parts separated by '.', got {len(parts)}")

    payload_b64, sig_b64 = parts[0], parts[1]
    if not payload_b64 or not sig_b64:
        raise TokenFormatError("Token parts cannot be empty")

    payload_bytes = b64url_decode(payload_b64)
    sig_bytes = b64url_decode(sig_b64)

    # Security: Ed25519 signatures are strictly 64 bytes; reject immediately if length differs
    if len(sig_bytes) != 64:
        raise TokenFormatError(f"Invalid signature length: expected 64 bytes, got {len(sig_bytes)}")

    return payload_bytes, sig_bytes


def decode_payload(payload_bytes: bytes) -> dict[str, Any]:
    """Decode and parse raw JSON payload bytes into a dictionary.

    Security Rule: Call this function ONLY after verifying the digital signature.
    """
    try:
        data = json.loads(payload_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Payload is not valid UTF-8 JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Decoded payload must be a JSON object")

    return data
