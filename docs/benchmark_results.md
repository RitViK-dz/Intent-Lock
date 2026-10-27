# IntentLock Performance Benchmark Results

> **Measurement Date**: 2026-10-27  
> **Environment**: Python 3.12.10 (tags/v3.12.10:0cc8128, Apr  8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)]  
> **Operating System**: Windows 11 (AMD64)  
> **Iterations**: 1000 independent transactions  

---

## 1. Executive Summary

IntentLock introduces cryptographic human approval verification without meaningful latency overhead for consumer or business checkouts.

- **Token Verification Median Latency**: **7.501 ms**
- **Token Verification 95th Percentile**: **18.701 ms**
- **Token Creation Median Latency**: **0.048 ms**

All measurements were dynamically computed using `time.perf_counter` across an isolated SQLite database and fresh Ed25519 keypair.

---

## 2. Detailed Verification Latency (`verify_checkout`)

The verifier executes signature verification with the Ed25519 public key, decodes token parameters, verifies constraints (payee, amount ceiling, item, merchant, agent, TTL), and atomically consumes the single-use nonce in SQLite.

| Metric | Latency (milliseconds) |
|---|---|
| **Runs Evaluated** | 1000 |
| **Median (p50)** | 7.501 ms |
| **95th Percentile (p95)** | 18.701 ms |
| **Maximum Latency** | 38.792 ms |
| **Mean Latency** | 9.213 ms |
| **Minimum Latency** | 5.535 ms |

---

## 3. Token Creation Latency (`create_token`)

Measures Ed25519 digital signature generation, JSON encoding, and Base64URL string formatting on the token issuer service.

| Metric | Latency (milliseconds) |
|---|---|
| **Median (p50)** | 0.048 ms |
| **95th Percentile (p95)** | 0.172 ms |
| **Maximum Latency** | 1.509 ms |
| **Mean Latency** | 0.079 ms |
| **Minimum Latency** | 0.042 ms |

---

## 4. Engineering & Presentation Notes

1. **Pure Asymmetric Math**: Verification relies strictly on the Ed25519 public key. There is zero symmetric secret sharing and no network RPC to the token issuer at checkout time.
2. **Atomic Replay Prevention**: The SQLite unique constraint on `used_nonces` guarantees atomic single-use semantics even under concurrent attempts.
3. **PROTOTYPE LIMITATION**: In a globally distributed high-throughput store, SQLite would be replaced by Redis with Lua scripting or a distributed relational database (e.g., PostgreSQL with row-level locking) for cross-datacenter nonce de-duplication.
