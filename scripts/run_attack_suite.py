"""IntentLock Phase 12b: 13-Attack Defense and Baseline Comparison Suite.

Executes all 13 attack scenarios against the store API:
1. Protected checkout (/store/checkout): Validates cryptographic IntentLock tokens.
   Verifies that the attack is blocked and the returned ReasonCode matches expectations.
2. Unprotected baseline (/store/checkout-unprotected): Demonstrates what happens without IntentLock.
   Verifies that the vulnerable store accepts the unapproved/hijacked request.

Outputs:
- Formatted table of Attack ID, Description, Expected Reason, Actual Reason, and Status (PASS/FAIL).
- Summary line: "13/13 attacks blocked"
- Summary line: "13/13 attacks succeeded without IntentLock"
"""

import warnings
warnings.filterwarnings("ignore")

import concurrent.futures
from pathlib import Path
import sys
import tempfile
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cryptography.hazmat.primitives.asymmetric import ed25519
from app.config import settings
from app.crypto import load_or_create_keypair
from app.db import init_db
from app.tokens import create_token, b64url_encode, b64url_decode, agent_pub_to_b64url
from app.verifier import ReasonCode
from app.main import app


def _create_token(priv_key, **overrides) -> str:
    """Helper to issue a legitimately formatted token."""
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
    }
    params.update(overrides)
    return create_token(priv_key, **params)


def run_attack_suite() -> tuple[list[dict], int, int]:
    """Execute all 13 attack scenarios and compute real-time outcomes."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_file = tmp_path / "attack_test.db"
        keys_dir = tmp_path / "attack_keys"
        attacker_keys_dir = tmp_path / "attacker_keys"

        # Point settings to isolated test environment
        object.__setattr__(settings, "db_path", db_file)
        object.__setattr__(settings, "keys_dir", keys_dir)

        init_db(db_file)
        priv_key, pub_key = load_or_create_keypair(keys_dir)
        attacker_priv, _ = load_or_create_keypair(attacker_keys_dir)

        # Ephemeral in-memory keypair for simulated agent
        agent_priv = ed25519.Ed25519PrivateKey.generate()
        agent_pub_b64 = agent_pub_to_b64url(agent_priv.public_key())

        client = TestClient(app)
        results = []
        blocked_count = 0
        unprotected_succeeded_count = 0

        # Define the 12 attack vectors
        attacks = [
            {
                "id": "A1",
                "desc": "Payee swapped to attacker account",
                "expected": ReasonCode.PAYEE_MISMATCH.value,
                "token": lambda: _create_token(priv_key, payee_id="STORE-ACCT-001"),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "ATTACKER-EVIL-007",
                },
            },
            {
                "id": "A2",
                "desc": "Amount above approved ceiling",
                "expected": ReasonCode.AMOUNT_EXCEEDS_LIMIT.value,
                "token": lambda: _create_token(priv_key, max_amount_cents=45000),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 90000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A3",
                "desc": "Item swapped to unauthorized product",
                "expected": ReasonCode.ITEM_MISMATCH.value,
                "token": lambda: _create_token(priv_key, item="laptop-14in"),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "gift-card-500usd",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A4",
                "desc": "Token replayed after legitimate checkout",
                "expected": ReasonCode.TOKEN_REPLAYED.value,
                "is_replay": True,
            },
            {
                "id": "A5",
                "desc": "Expired token submitted",
                "expected": ReasonCode.TOKEN_EXPIRED.value,
                "token": lambda: _create_token(priv_key, now=100000, ttl_seconds=10),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A6",
                "desc": "Payload tampered (flipped bit)",
                "expected": ReasonCode.BAD_SIGNATURE.value,
                "token": lambda: _tamper_token(_create_token(priv_key)),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A7",
                "desc": "Attacker forged signature (foreign key)",
                "expected": ReasonCode.BAD_SIGNATURE.value,
                "token": lambda: _create_token(attacker_priv),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A8",
                "desc": "Store merchant mismatch",
                "expected": ReasonCode.MERCHANT_MISMATCH.value,
                "token": lambda: _create_token(priv_key, merchant_id="demo-store"),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "evil-rogue-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A9",
                "desc": "Rogue agent mismatch",
                "expected": ReasonCode.AGENT_MISMATCH.value,
                "token": lambda: _create_token(priv_key, agent_id="shopper-agent-1"),
                "req": {
                    "agent_id": "rogue-agent-99",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A10",
                "desc": "Missing or empty token",
                "expected": ReasonCode.MISSING_TOKEN.value,
                "token": lambda: "",
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A11",
                "desc": "Malformed token structure",
                "expected": ReasonCode.MALFORMED_TOKEN.value,
                "token": lambda: "garbage.token.with.bad.dots",
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                },
            },
            {
                "id": "A12",
                "desc": "Concurrent replay race condition",
                "expected": ReasonCode.TOKEN_REPLAYED.value,
                "is_race": True,
            },
            {
                "id": "A13",
                "desc": "Stolen token used without agent key",
                "expected": ReasonCode.BAD_AGENT_PROOF.value,
                "token": lambda: _create_token(priv_key, agent_pub=agent_pub_b64),
                "req": {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                    "agent_proof": None,
                },
            },
        ]

        # Execute each attack
        for atk in attacks:
            atk_id = atk["id"]
            desc = atk["desc"]
            expected = atk["expected"]

            if atk.get("is_replay"):
                # A4: Legitimate checkout first, then replayed checkout
                valid_tok = _create_token(priv_key)
                req_body = {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                    "token": valid_tok,
                }
                # Legitimate first run
                first_resp = client.post("/store/checkout", json=req_body)
                if first_resp.status_code != 200:
                    actual = f"SETUP_FAIL_{first_resp.status_code}"
                else:
                    # Replay attempt (must be blocked)
                    replay_resp = client.post("/store/checkout", json=req_body)
                    actual = replay_resp.json().get("reason", f"HTTP_{replay_resp.status_code}")

                # Unprotected run (duplicate charge succeeds)
                unprot_resp1 = client.post("/store/checkout-unprotected", json=req_body)
                unprot_resp2 = client.post("/store/checkout-unprotected", json=req_body)
                unprot_ok = (unprot_resp1.status_code == 200 and unprot_resp2.status_code == 200)

            elif atk.get("is_race"):
                # A12: 10 concurrent requests with the exact same token
                race_tok = _create_token(priv_key)
                req_body = {
                    "agent_id": "shopper-agent-1",
                    "merchant_id": "demo-store",
                    "item": "laptop-14in",
                    "amount_cents": 45000,
                    "payee_id": "STORE-ACCT-001",
                    "token": race_tok,
                }

                def send_req(endpoint):
                    return client.post(endpoint, json=req_body)

                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(send_req, "/store/checkout") for _ in range(10)]
                    responses = [f.result() for f in futures]

                approved_count = sum(1 for r in responses if r.status_code == 200)
                replayed_count = sum(1 for r in responses if r.status_code == 403 and r.json().get("reason") == expected)

                actual = expected if (approved_count == 1 and replayed_count == 9) else f"RACE_{approved_count}app_{replayed_count}rep"

                # Unprotected race: all 10 succeed
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                    unprot_futures = [executor.submit(send_req, "/store/checkout-unprotected") for _ in range(10)]
                    unprot_responses = [f.result() for f in unprot_futures]

                unprot_ok = all(r.status_code == 200 for r in unprot_responses)

            else:
                token_val = atk["token"]()
                req_body = dict(atk["req"])
                req_body["token"] = token_val

                # Protected checkout
                prot_resp = client.post("/store/checkout", json=req_body)
                actual = prot_resp.json().get("reason", f"HTTP_{prot_resp.status_code}")

                # Unprotected checkout with hijacked payload
                unprot_resp = client.post("/store/checkout-unprotected", json=req_body)
                unprot_ok = (unprot_resp.status_code == 200)

            passed = (actual == expected)
            if passed:
                blocked_count += 1
            if unprot_ok:
                unprotected_succeeded_count += 1

            results.append({
                "id": atk_id,
                "desc": desc,
                "expected": expected,
                "actual": actual,
                "status": "PASS" if passed else "FAIL",
                "unprotected_succeeded": unprot_ok,
            })

    return results, blocked_count, unprotected_succeeded_count


def _tamper_token(token: str) -> str:
    """Flip one byte in the token payload to break signature."""
    payload_b64, sig_b64 = token.split(".")
    payload_bytes = bytearray(b64url_decode(payload_b64))
    payload_bytes[4] ^= 0x01
    return f"{b64url_encode(bytes(payload_bytes))}.{sig_b64}"


def print_attack_table(results: list[dict], blocked_count: int, unprot_count: int) -> None:
    """Print clean ASCII table and summary stats."""
    total = len(results)

    print("\n" + "=" * 90)
    print("                  IntentLock 13-Attack Defense Evaluation Suite")
    print("=" * 90)

    # Format header
    header_fmt = "| {0:<4} | {1:<35} | {2:<22} | {3:<22} | {4:<6} |"
    divider    = "+------+-------------------------------------+------------------------+------------------------+--------+"
    
    print(divider)
    print(header_fmt.format("ID", "Attack Description", "Expected Reason", "Actual Reason", "Status"))
    print(divider)

    for r in results:
        print(header_fmt.format(r["id"], r["desc"], r["expected"], r["actual"], r["status"]))

    print(divider)
    print(f"\nProtected verification: {blocked_count}/{total} attacks blocked")
    print(f"Unprotected baseline:   {unprot_count}/{total} attacks succeeded without IntentLock\n")


def main():
    results, blocked, unprot = run_attack_suite()
    print_attack_table(results, blocked, unprot)

    # Exit with code 1 if any attack failed to be blocked
    if blocked != len(results):
        sys.exit(1)


if __name__ == "__main__":
    main()
