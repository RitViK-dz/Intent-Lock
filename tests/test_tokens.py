"""Security and functional tests for IntentLock authorization tokens."""

import pytest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.crypto import load_or_create_keypair, verify
from app.tokens import (
    create_token,
    parse_token,
    decode_payload,
    TokenFormatError,
    b64url_encode,
    b64url_decode,
)


def _sample_token_args(private_key: ed25519.Ed25519PrivateKey, **overrides) -> dict:
    """Helper providing standard valid arguments for create_token."""
    base = {
        "private_key": private_key,
        "user_id": "demo-user",
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "action": "purchase",
        "item": "laptop-14in",
        "max_amount_cents": 45000,
        "currency": "USD",
        "payee_id": "STORE-ACCT-001",
        "ttl_seconds": 300,
        "now": 1700000000,
    }
    base.update(overrides)
    return base


def test_token_roundtrip_valid_signature(tmp_path: Path):
    """Verify create_token -> parse_token -> verify signature -> decode_payload succeeds."""
    priv_key, pub_key = load_or_create_keypair(tmp_path)
    args = _sample_token_args(priv_key)

    token = create_token(**args)
    assert isinstance(token, str)
    assert "." in token

    # Step 1: Parse token into exact payload and signature bytes
    payload_bytes, sig_bytes = parse_token(token)

    # Step 2: Verify signature over raw payload bytes
    is_valid = verify(pub_key, sig_bytes, payload_bytes)
    assert is_valid is True

    # Step 3: Decode payload ONLY after signature verification succeeds
    payload = decode_payload(payload_bytes)
    assert payload["v"] == 1
    assert payload["user_id"] == "demo-user"
    assert payload["agent_id"] == "shopper-agent-1"
    assert payload["merchant_id"] == "demo-store"
    assert payload["action"] == "purchase"
    assert payload["item"] == "laptop-14in"
    assert payload["max_amount_cents"] == 45000
    assert payload["currency"] == "USD"
    assert payload["payee_id"] == "STORE-ACCT-001"
    assert payload["iat"] == 1700000000
    assert payload["exp"] == 1700000300
    assert len(payload["nonce"]) == 32  # 16 random bytes as hex


def test_token_payload_tampering_fails_verification(tmp_path: Path):
    """Verify that changing one byte in the token payload invalidates the signature."""
    priv_key, pub_key = load_or_create_keypair(tmp_path)
    token = create_token(**_sample_token_args(priv_key))

    payload_b64, sig_b64 = token.split(".")
    payload_bytes = b64url_decode(payload_b64)
    sig_bytes = b64url_decode(sig_b64)

    # Tamper with one byte in the payload
    tampered_bytes = bytearray(payload_bytes)
    tampered_bytes[-2] ^= 0x01  # mutate second to last byte

    assert verify(pub_key, sig_bytes, bytes(tampered_bytes)) is False


def test_token_signed_with_different_keypair_fails(tmp_path: Path):
    """Verify that a token signed with keypair A fails verification under keypair B."""
    priv_key_a, _ = load_or_create_keypair(tmp_path / "issuer_a")
    _, pub_key_b = load_or_create_keypair(tmp_path / "issuer_b")

    token_a = create_token(**_sample_token_args(priv_key_a))
    payload_bytes, sig_bytes = parse_token(token_a)

    # Verifying against issuer B's public key must fail
    assert verify(pub_key_b, sig_bytes, payload_bytes) is False


@pytest.mark.parametrize(
    "bad_token",
    [
        "",  # empty string
        "not-a-token",  # no dot
        "part1.part2.part3",  # too many parts
        "invalid_base64!.valid_sig",  # invalid characters in base64
        "valid_payload.not_base64_sig!@#",  # invalid signature encoding
        "payload.",  # missing signature part
        ".signature",  # missing payload part
        12345,  # non-string
    ],
)
def test_malformed_token_raises_token_format_error(bad_token):
    """Verify that any malformed token input raises TokenFormatError."""
    with pytest.raises(TokenFormatError):
        parse_token(bad_token)


def test_thousand_tokens_have_unique_nonces(tmp_path: Path):
    """Verify that 1000 generated tokens have 1000 unique nonces (no collision)."""
    priv_key, _ = load_or_create_keypair(tmp_path)
    args = _sample_token_args(priv_key)

    nonces = set()
    for _ in range(1000):
        token = create_token(**args)
        payload_bytes, _ = parse_token(token)
        payload = decode_payload(payload_bytes)
        nonces.add(payload["nonce"])

    assert len(nonces) == 1000


def test_max_amount_cents_stored_strictly_as_integer(tmp_path: Path):
    """Verify that max_amount_cents is stored and decoded strictly as an integer, never float."""
    priv_key, _ = load_or_create_keypair(tmp_path)
    token = create_token(**_sample_token_args(priv_key, max_amount_cents=9999))

    payload_bytes, _ = parse_token(token)
    payload = decode_payload(payload_bytes)

    assert isinstance(payload["max_amount_cents"], int)
    assert not isinstance(payload["max_amount_cents"], float)
    assert payload["max_amount_cents"] == 9999


def test_b64url_helpers_no_padding():
    """Verify base64url encoding uses URL-safe alphabet and omits trailing '=' padding."""
    raw = b"Hello, IntentLock base64 test payload!"
    encoded = b64url_encode(raw)

    assert "=" not in encoded
    assert "+" not in encoded
    assert "/" not in encoded

    decoded = b64url_decode(encoded)
    assert decoded == raw


def test_token_with_agent_pub_sets_version_two(tmp_path: Path):
    """Verify create_token with agent_pub sets v=2 and embeds agent_pub."""
    priv_key, _ = load_or_create_keypair(tmp_path)
    args = _sample_token_args(priv_key, agent_pub="test_agent_pub_base64url_string")

    token = create_token(**args)
    payload_bytes, _ = parse_token(token)
    payload = decode_payload(payload_bytes)

    assert payload["v"] == 2
    assert payload["agent_pub"] == "test_agent_pub_base64url_string"


def test_token_without_agent_pub_stays_version_one(tmp_path: Path):
    """Verify create_token without agent_pub maintains v=1 and does not have agent_pub key."""
    priv_key, _ = load_or_create_keypair(tmp_path)
    args = _sample_token_args(priv_key, agent_pub=None)

    token = create_token(**args)
    payload_bytes, _ = parse_token(token)
    payload = decode_payload(payload_bytes)

    assert payload["v"] == 1
    assert "agent_pub" not in payload


def test_compute_agent_proof_bytes_canonical_format():
    """Verify compute_agent_proof_bytes formats exact JSON with sort_keys=True and separators=(',', ':')."""
    from app.tokens import compute_agent_proof_bytes

    proof_bytes = compute_agent_proof_bytes(
        agent_id="agent-007",
        merchant_id="merchant-abc",
        item="item-xyz",
        amount_cents=5000,
        payee_id="PAYEE-1",
        nonce="testnonce12345",
    )
    expected = b'{"agent_id":"agent-007","amount_cents":5000,"item":"item-xyz","merchant_id":"merchant-abc","nonce":"testnonce12345","payee_id":"PAYEE-1"}'
    assert proof_bytes == expected
