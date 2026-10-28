# IntentLock System Architecture

> **Technical Reference Specification & Engineering Design**

---

## 1. System Overview

IntentLock introduces a cryptographic control layer between autonomous AI agents and sensitive downstream APIs (e.g., e-commerce checkouts, banking transfers, cloud infrastructure mutations).

When an AI agent is compromised via indirect prompt injection, its cognitive reasoning cannot be trusted. IntentLock assumes the agent is completely compromised, preventing damage by enforcing an invariant: **No financial action may execute unless accompanied by a cryptographically signed human approval token matching the exact action parameters.**

```
+-----------------------------------------------------------------------------------------+
|                                    INTENTLOCK SYSTEM                                    |
|                                                                                         |
|  +---------------------+      Propose Intent      +----------------------------------+  |
|  |  Autonomous Agent   | -----------------------> |    Approval Dashboard & Issuer   |  |
|  |  (Simulated Hijack) |                          | (Human Review, Ed25519 Token)    |  |
|  +---------------------+                          +----------------------------------+  |
|             |                                                      |                    |
|             | (Hijacked checkout request                           | Mints single-use   |
|             |  with legitimate token)                              | signed token       |
|             v                                                      v                    |
|  +-----------------------------------------------------------------------------------+  |
|  |                                  MERCHANT STORE                                   |  |
|  |                                                                                   |  |
|  |  /store/checkout (Protected)              /store/checkout-unprotected             |  |
|  |  - Loads Issuer Public Key (No privkey)   - Baseline vulnerable endpoint          |  |
|  |  - Verifies Ed25519 signature             - Blindly creates order                 |  |
|  |  - Validates payee, item, ceiling, TTL    - Shows attack succeeds                 |  |
|  |  - Consumes single-use nonce in SQLite                                            |  |
|  +-----------------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Core Components

### 2.1. The Proposing Agent (`agent_sim/`)
- Interacts with untrusted external content (e.g., web store catalogs, third-party emails).
- Proposes candidate actions to `POST /api/intents` containing:
  - `agent_id`: Identifier of the agent proposing the action.
  - `merchant_id`: Destination merchant identifier.
  - `item`: Specific item description or SKU.
  - `amount_cents`: Total spending ceiling in integer cents.
  - `payee_id`: Intended bank/settlement account.
  - `summary`: Human-readable justification of the purchase.
  - `agent_pub`: Optional Base64URL-encoded raw 32-byte Ed25519 public key for proof-of-possession binding. The agent private key is held strictly in memory only (never written to disk or the repository).
- Receives a token upon human approval and presents it to merchant checkout endpoints along with an `agent_proof` signature for `v=2` tokens.

### 2.2. The IntentLock Authority (`app/routers/intents.py`, `app/tokens.py`, `app/crypto.py`)
- **Intent Storage**: Persists proposed intents in SQLite with status `pending`.
- **Human Approval Dashboard**: Exposes an interactive web UI (`/index.html`) where humans inspect proposed parameters and decide `approve` or `reject`.
- **Token Issuer**: Upon explicit human approval, generates a cryptographically signed authorization token using the authority's private Ed25519 key.
- **Audit Logging**: Logs every intent transition (created, approved, rejected) to an append-only audit trail (`audit_log` table), strictly omitting raw token strings and private keys.

### 2.3. The Store Verifier Engine (`app/verifier.py`, `app/routers/store.py`)
- Deployed at the merchant service.
- **Zero Secrets Invariant**: Operates using **only** the authority's Ed25519 public key. The store has zero access to the private signing key.
- Validates tokens step-by-step against the incoming `CheckoutRequest`:
  1. Token presence & base64url parsing.
  2. Ed25519 cryptographic signature verification against raw payload bytes.
  3. JSON payload decoding & structural validation.
  4. Expiration check (`exp + clock_skew >= now`).
  5. Merchant binding (`aud == store_id == request.merchant_id`).
  6. Agent identity binding (`payload.agent_id == request.agent_id`).
  7. Item binding (`payload.item == request.item`).
  8. Payee account matching (`payload.payee_id == request.payee_id`).
  9. Amount ceiling check (`request.amount_cents <= payload.max_amount_cents`).
  10. Agent Proof-of-Possession check: If the token contains `agent_pub` (`v=2` tokens), a valid `agent_proof` is strictly required (`BAD_AGENT_PROOF` on missing or invalid proof). The agent proof signs canonical JSON (`sort_keys=True`, `separators=(',', ':')`, UTF-8) over `{agent_id, merchant_id, item, amount_cents, payee_id, nonce}`, unlike the authority token which signs the exact raw payload bytes sent. The agent private key is kept strictly in memory.
  11. Single-use nonce consumption (`consume_nonce(payload.nonce)`): Executed atomically as the LAST step so that a failed agent proof or parameter mismatch never burns a legitimate token.
- Rejects invalid requests with HTTP `403 Forbidden` and explicit machine-readable `ReasonCode` values.

---

## 3. Cryptographic Token Specification

### 3.1. Construction
IntentLock authorization tokens adopt an RFC 7515 / RFC 7519 inspired two-part compact serialization:
```
<base64url(payload_json)>.<base64url(ed25519_signature)>
```
- `payload_json`: compact JSON (`separators=(',', ':')`), UTF-8 encoded. The signature is computed over these exact bytes, and the verifier checks the signature over the bytes it receives, without re-serialising. No canonicalisation step is needed.
- `ed25519_signature`: 64-byte Ed25519 digital signature generated over the exact UTF-8 payload bytes.
- Base64URL encoding is unpadded (RFC 4648 §5), ensuring safe transport in HTTP headers, JSON bodies, or query parameters.

### 3.2. Payload Schema
```json
{
  "v": 2,
  "nonce": "7a305f2c41c7423ba4c017efad8d7c92",
  "user_id": "demo-user",
  "agent_id": "shopper-agent-1",
  "merchant_id": "demo-store",
  "action": "purchase",
  "item": "laptop-14in",
  "max_amount_cents": 45000,
  "currency": "USD",
  "payee_id": "STORE-ACCT-001",
  "iat": 1700000000,
  "exp": 1700000300,
  "agent_pub": "A3YMDWlx5cGBAfKlLqtaKJyN8aH7dlFvo7WDqaaqd0g"
}
```
*(Tokens issued without `agent_pub` use `"v": 1` and omit the `agent_pub` field).*

---

## 4. Database Schema & Replay Prevention

IntentLock utilizes an SQLite database configured in Write-Ahead Logging (`WAL`) mode with a busy timeout of 15 seconds to support high local concurrency.

### 4.1. Tables

#### `intents`
Tracks proposals submitted by agents and human decisions.
```sql
CREATE TABLE intents (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    merchant_id TEXT,
    item TEXT,
    amount_cents INTEGER,
    payee_id TEXT,
    summary TEXT,
    status TEXT CHECK (status IN ('pending', 'approved', 'rejected')),
    created_at INTEGER,
    decided_at INTEGER,
    agent_pub TEXT
);
```

#### `used_nonces`
Enforces atomic single-use semantics.
```sql
CREATE TABLE used_nonces (
    nonce TEXT PRIMARY KEY,
    used_at INTEGER,
    merchant_id TEXT
);
```

#### `audit_log`
Append-only forensic audit trail.
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER,
    event TEXT,
    actor TEXT,
    intent_id TEXT,
    detail_json TEXT
);
```

#### `orders`
Store settlement records indicating processing endpoint and recipient payee.
```sql
CREATE TABLE orders (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    merchant_id TEXT,
    item TEXT,
    amount_cents INTEGER,
    payee_id TEXT,
    endpoint TEXT,
    created_at INTEGER
);
```

### 4.2. Atomic Nonce Consumption (TOCTOU Prevention)
A naive verifier might execute:
```sql
-- VULNERABLE PATTERN (DO NOT USE)
SELECT 1 FROM used_nonces WHERE nonce = ?;
-- (Race condition: another thread inserts here)
INSERT INTO used_nonces VALUES (?);
```
IntentLock eliminates Time-of-Check to Time-of-Use (TOCTOU) race conditions by attempting an immediate `INSERT INTO used_nonces (nonce, used_at, merchant_id) VALUES (?, ?, ?);`. Because `nonce` is the `PRIMARY KEY`, SQLite's underlying B-tree engine enforces uniqueness atomically:
- If the insertion succeeds, the token is consumed for the first and only time (`True`).
- If SQLite throws an `IntegrityError`, the token was already consumed (`False` -> `TOKEN_REPLAYED`).
- Nonce consumption is executed as the **final step** in verification so that malformed or unauthorized requests do not accidentally burn a legitimate token.

---

## 5. Endpoints Overview

| Method | Endpoint | Purpose | Protection |
|---|---|---|---|
| `POST` | `/api/intents` | Propose candidate agent action | Public agent API |
| `GET` | `/api/intents` | Query pending/decided intents | Approval dashboard |
| `GET` | `/api/intents/{id}` | Get intent details | Approval dashboard |
| `POST` | `/api/intents/{id}/approve` | Mint Ed25519 authorization token | Human approval only |
| `POST` | `/api/intents/{id}/reject` | Reject proposal | Human approval only |
| `GET` | `/api/public-key` | Download issuer Ed25519 public key | Public PEM |
| `GET` | `/api/audit` | Query append-only audit trail | Read-only audit |
| `POST` | `/store/checkout` | Protected merchant checkout | Requires valid IntentLock token |
| `POST` | `/store/checkout-unprotected` | Vulnerable baseline checkout | Demo only (shows exploit) |
| `GET` | `/store/catalog` | Mock store product catalog | Public catalog |
| `GET` | `/store/orders` | Store settlement ledger | Audit & demonstration |
| `POST` | `/api/demo/reset` | Clear simulation state | Gated: `DEMO_MODE=true` only |
| `POST` | `/api/demo/run` | Execute simulated attack scenario | Demo runner |
