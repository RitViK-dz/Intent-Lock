"""The IntentLock 12-attack suite and authorization invariant tests.

Covers:
- Happy path (exact match)
- Amount lower than maximum ceiling (allowed)
- A1: Payee swapped (attacker redirects payment to malicious account)
- A2: Amount above maximum spending ceiling
- A3: Item swapped (attacker attempts unauthorized product checkout)
- A4: Token replayed after legitimate use
- A5: Expired token
- A6: Payload tampered (flipped bit)
- A7: Token signed by attacker's foreign keypair
- A8: Token used at a different merchant store
- A9: Token used by a different agent ID
- A10: Missing/empty token
- A11: Malformed token string
- A12: Race condition: 10 concurrent threads submit the exact same token simultaneously
"""

import concurrent.futures
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.crypto import load_or_create_keypair, sign
from app.tokens import create_token, b64url_encode, b64url_decode
from app.db import init_db
from app.verifier import (
    ReasonCode,
    CheckoutRequest,
    verify_checkout,
)


@pytest.fixture
def test_env(tmp_path: Path):
    """Fixture providing initialized keypair, test database, and store configuration."""
    db_file = tmp_path / "verifier_test.db"
    init_db(db_file)

    keys_dir = tmp_path / "keys"
    priv_key, pub_key = load_or_create_keypair(keys_dir)

    attacker_dir = tmp_path / "attacker_keys"
    attacker_priv, _ = load_or_create_keypair(attacker_dir)

    return {
        "db_path": db_file,
        "priv_key": priv_key,
        "pub_key": pub_key,
        "attacker_priv": attacker_priv,
        "store_id": "demo-store",
    }


def _create_approved_token(priv_key: ed25519.Ed25519PrivateKey, **overrides) -> str:
    """Helper creating a legitimately approved token with default standard parameters."""
    params = {
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
    params.update(overrides)
    return create_token(priv_key, **params)


def _default_request(**overrides) -> CheckoutRequest:
    """Helper creating a checkout request matching the approved token default parameters."""
    params = {
        "agent_id": "shopper-agent-1",
        "merchant_id": "demo-store",
        "item": "laptop-14in",
        "amount_cents": 45000,
        "payee_id": "STORE-ACCT-001",
    }
    params.update(overrides)
    return CheckoutRequest(**params)


def test_happy_path_checkout_approved(test_env):
    """Happy path: valid token matching request exactly is APPROVED."""
    token = _create_approved_token(test_env["priv_key"], now=1700000000)
    req = _default_request()

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is True
    assert res.reason == ReasonCode.APPROVED
    assert res.nonce is not None
    assert res.elapsed_ms > 0


def test_lower_amount_than_maximum_approved(test_env):
    """An approved token with max 45000 cents allows a checkout for 39900 cents."""
    token = _create_approved_token(test_env["priv_key"], max_amount_cents=45000, now=1700000000)
    req = _default_request(amount_cents=39900)

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is True
    assert res.reason == ReasonCode.APPROVED


def test_a1_payee_swapped_blocked(test_env):
    """A1 Attack: Hijacked agent attempts to route payment to attacker payee account."""
    token = _create_approved_token(test_env["priv_key"], payee_id="STORE-ACCT-001", now=1700000000)
    # Hijacked request diverts funds to attacker account
    req = _default_request(payee_id="ATTACKER-EVIL-007")

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.PAYEE_MISMATCH


def test_a2_amount_above_maximum_blocked(test_env):
    """A2 Attack: Hijacked agent attempts to charge more than the user-approved maximum ceiling."""
    token = _create_approved_token(test_env["priv_key"], max_amount_cents=45000, now=1700000000)
    # Hijacked request exceeds limit by 1 cent
    req = _default_request(amount_cents=45001)

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.AMOUNT_EXCEEDS_LIMIT


def test_a3_item_swapped_blocked(test_env):
    """A3 Attack: Hijacked agent attempts to checkout a different item than approved."""
    token = _create_approved_token(test_env["priv_key"], item="laptop-14in", now=1700000000)
    # Hijacked request attempts to purchase luxury gift card
    req = _default_request(item="gift-card-500usd")

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.ITEM_MISMATCH


def test_a4_token_replayed_blocked(test_env):
    """A4 Attack: Token replayed after a previous successful use is blocked atomically."""
    token = _create_approved_token(test_env["priv_key"], now=1700000000)
    req = _default_request()

    # First checkout: succeeds
    first_res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )
    assert first_res.allowed is True
    assert first_res.reason == ReasonCode.APPROVED

    # Second checkout (replay): blocked
    second_res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000060,
        db_path=test_env["db_path"],
    )
    assert second_res.allowed is False
    assert second_res.reason == ReasonCode.TOKEN_REPLAYED


def test_a5_expired_token_blocked(test_env):
    """A5 Attack: Token presented after TTL expiry (with clock skew window elapsed) is blocked."""
    # Issued at 1700000000 with 300s TTL (expires at 1700000300)
    token = _create_approved_token(test_env["priv_key"], ttl_seconds=300, now=1700000000)
    req = _default_request()

    # Request arrives at 1700000310 (beyond 300s TTL + 5s skew)
    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000310,
        skew_seconds=5,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.TOKEN_EXPIRED


def test_a6_payload_tampered_blocked(test_env):
    """A6 Attack: Attacker tampers with token payload bytes; signature verification fails."""
    token = _create_approved_token(test_env["priv_key"], now=1700000000)
    req = _default_request()

    payload_b64, sig_b64 = token.split(".")
    payload_bytes = bytearray(b64url_decode(payload_b64))
    # Flip one byte in the payload
    payload_bytes[5] ^= 0x01
    tampered_token = f"{b64url_encode(bytes(payload_bytes))}.{sig_b64}"

    res = verify_checkout(
        token=tampered_token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.BAD_SIGNATURE


def test_a7_token_signed_by_attacker_key_blocked(test_env):
    """A7 Attack: Token signed by an unauthorized third-party keypair is rejected."""
    # Signed by attacker's private key instead of legitimate authority
    token = _create_approved_token(test_env["attacker_priv"], now=1700000000)
    req = _default_request()

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.BAD_SIGNATURE


def test_a8_token_used_at_different_merchant_blocked(test_env):
    """A8 Attack: Token approved for demo-store is submitted to attacker-store."""
    token = _create_approved_token(test_env["priv_key"], merchant_id="demo-store", now=1700000000)
    req = _default_request(merchant_id="evil-rogue-store")

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.MERCHANT_MISMATCH


def test_a9_token_used_by_different_agent_blocked(test_env):
    """A9 Attack: Token issued to shopper-agent-1 is submitted by unauthorized rogue-agent."""
    token = _create_approved_token(test_env["priv_key"], agent_id="shopper-agent-1", now=1700000000)
    req = _default_request(agent_id="rogue-malicious-agent")

    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.AGENT_MISMATCH


def test_a10_missing_token_blocked(test_env):
    """A10 Attack: Request submitted without any token."""
    req = _default_request()

    res_none = verify_checkout(
        token=None,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )
    assert res_none.allowed is False
    assert res_none.reason == ReasonCode.MISSING_TOKEN

    res_empty = verify_checkout(
        token="",
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )
    assert res_empty.allowed is False
    assert res_empty.reason == ReasonCode.MISSING_TOKEN


def test_a11_malformed_token_blocked(test_env):
    """A11 Attack: Malformed token strings (no dots, bad base64) are blocked gracefully."""
    req = _default_request()

    for bad in ["not_a_valid_token", "missingdot", "part1.part2.part3", "bad_b64@.sig"]:
        res = verify_checkout(
            token=bad,
            request=req,
            public_key=test_env["pub_key"],
            store_id=test_env["store_id"],
            now=1700000050,
            db_path=test_env["db_path"],
        )
        assert res.allowed is False
        assert res.reason == ReasonCode.MALFORMED_TOKEN


def test_a12_race_ten_threads_one_approved(test_env):
    """A12 Attack: 10 concurrent threads submit the exact same valid token at once. Exactly one APPROVED."""
    token = _create_approved_token(test_env["priv_key"], now=1700000000)
    req = _default_request()
    num_threads = 10

    def submit_request():
        return verify_checkout(
            token=token,
            request=req,
            public_key=test_env["pub_key"],
            store_id=test_env["store_id"],
            now=1700000050,
            db_path=test_env["db_path"],
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(submit_request) for _ in range(num_threads)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    # Exactly one request must be APPROVED
    approved_count = sum(1 for r in results if r.allowed and r.reason == ReasonCode.APPROVED)
    assert approved_count == 1

    # Remaining 9 requests must be blocked with TOKEN_REPLAYED
    replayed_count = sum(1 for r in results if not r.allowed and r.reason == ReasonCode.TOKEN_REPLAYED)
    assert replayed_count == num_threads - 1


def test_a13_stolen_token_without_agent_private_key_blocked(test_env):
    """A13 Attack: Attacker steals a v=2 token bound to agent_pub.

    Without the agent's private key, the stolen token cannot produce a valid
    proof-of-possession signature. Verifier blocks it with BAD_AGENT_PROOF, and
    does NOT consume the nonce (the legitimate token is not burned).
    """
    # 1. Legitimate agent has its own Ed25519 keypair in memory
    agent_priv = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    agent_pub_raw = agent_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    agent_pub_b64 = b64url_encode(agent_pub_raw)

    # 2. Token issued with agent_pub (v=2 token)
    token = _create_approved_token(
        test_env["priv_key"],
        agent_pub=agent_pub_b64,
        now=1700000000,
    )

    # 3. Attacker intercepts/steals token, submits checkout with NO agent proof
    stolen_req = _default_request(agent_proof=None)
    res_no_proof = verify_checkout(
        token=token,
        request=stolen_req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )
    assert res_no_proof.allowed is False
    assert res_no_proof.reason == ReasonCode.BAD_AGENT_PROOF

    # 4. Attacker attempts to forge proof using their own private key
    from app.tokens import compute_agent_proof_bytes
    attacker_proof_bytes = compute_agent_proof_bytes(
        agent_id=stolen_req.agent_id,
        merchant_id=stolen_req.merchant_id,
        item=stolen_req.item,
        amount_cents=stolen_req.amount_cents,
        payee_id=stolen_req.payee_id,
        nonce=res_no_proof.nonce,
    )
    forged_proof = b64url_encode(sign(test_env["attacker_priv"], attacker_proof_bytes))
    forged_req = _default_request(agent_proof=forged_proof)

    res_forged = verify_checkout(
        token=token,
        request=forged_req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )
    assert res_forged.allowed is False
    assert res_forged.reason == ReasonCode.BAD_AGENT_PROOF

    # 5. INVARIANT: Nonce was NOT burned by failed proof attempts!
    # The legitimate agent can still check out using the token with valid proof.
    valid_proof_bytes = compute_agent_proof_bytes(
        agent_id="shopper-agent-1",
        merchant_id="demo-store",
        item="laptop-14in",
        amount_cents=45000,
        payee_id="STORE-ACCT-001",
        nonce=res_no_proof.nonce,
    )
    valid_proof = b64url_encode(sign(agent_priv, valid_proof_bytes))
    legit_req = _default_request(agent_proof=valid_proof)

    res_legit = verify_checkout(
        token=token,
        request=legit_req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )
    assert res_legit.allowed is True
    assert res_legit.reason == ReasonCode.APPROVED


def test_agent_proof_valid_passes(test_env):
    """Valid proof-of-possession matching token agent_pub and request parameters is APPROVED."""
    agent_priv = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    agent_pub_raw = agent_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    agent_pub_b64 = b64url_encode(agent_pub_raw)

    token = _create_approved_token(
        test_env["priv_key"],
        agent_pub=agent_pub_b64,
        now=1700000000,
    )

    from app.tokens import parse_token, decode_payload, compute_agent_proof_bytes
    payload = decode_payload(parse_token(token)[0])
    nonce = payload["nonce"]

    proof_bytes = compute_agent_proof_bytes(
        agent_id="shopper-agent-1",
        merchant_id="demo-store",
        item="laptop-14in",
        amount_cents=45000,
        payee_id="STORE-ACCT-001",
        nonce=nonce,
    )
    proof_sig = b64url_encode(sign(agent_priv, proof_bytes))

    req = _default_request(agent_proof=proof_sig)
    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is True
    assert res.reason == ReasonCode.APPROVED


def test_agent_proof_over_different_fields_fails(test_env):
    """Proof generated over different fields (e.g. different amount) fails verification."""
    agent_priv = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    agent_pub_raw = agent_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    agent_pub_b64 = b64url_encode(agent_pub_raw)

    token = _create_approved_token(
        test_env["priv_key"],
        agent_pub=agent_pub_b64,
        now=1700000000,
    )

    from app.tokens import parse_token, decode_payload, compute_agent_proof_bytes
    payload = decode_payload(parse_token(token)[0])
    nonce = payload["nonce"]

    # Sign over 10000 cents instead of 45000 cents
    proof_bytes = compute_agent_proof_bytes(
        agent_id="shopper-agent-1",
        merchant_id="demo-store",
        item="laptop-14in",
        amount_cents=10000,  # mismatch!
        payee_id="STORE-ACCT-001",
        nonce=nonce,
    )
    proof_sig = b64url_encode(sign(agent_priv, proof_bytes))

    req = _default_request(agent_proof=proof_sig)  # req has amount_cents=45000
    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.BAD_AGENT_PROOF


def test_agent_proof_missing_on_v2_token_fails(test_env):
    """A v=2 token presented without agent_proof is rejected with BAD_AGENT_PROOF."""
    agent_priv = ed25519.Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    agent_pub_raw = agent_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    agent_pub_b64 = b64url_encode(agent_pub_raw)

    token = _create_approved_token(
        test_env["priv_key"],
        agent_pub=agent_pub_b64,
        now=1700000000,
    )

    req = _default_request(agent_proof=None)
    res = verify_checkout(
        token=token,
        request=req,
        public_key=test_env["pub_key"],
        store_id=test_env["store_id"],
        now=1700000050,
        db_path=test_env["db_path"],
    )

    assert res.allowed is False
    assert res.reason == ReasonCode.BAD_AGENT_PROOF
