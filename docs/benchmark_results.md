# IntentLock Performance Benchmark Results

> **Measurement Date**: 2026-10-27  
> **Environment**: Python 3.12.10 (tags/v3.12.10:0cc8128, Apr  8 2025, 12:21:36) [MSC v.1943 64 bit (AMD64)]  
> **Operating System**: Windows 11 (AMD64)  
> **Iterations**: 1000 independent transactions  

---

## 1. Executive Summary

IntentLock introduces cryptographic human approval verification without meaningful latency overhead for consumer or business checkouts.

- **Token Verification Median Latency**: **5.928 ms**
- **Token Verification 95th Percentile**: **8.773 ms**
- **Token Creation Median Latency**: **0.045 ms**

All measurements were dynamically computed using `time.perf_counter` across an isolated SQLite database and fresh Ed25519 keypair.

---

## 2. Detailed Verification Latency (`verify_checkout`)

The verifier executes signature verification with the Ed25519 public key, decodes token parameters, verifies constraints (payee, amount ceiling, item, merchant, agent, TTL), and atomically consumes the single-use nonce in SQLite.

| Metric | Latency (milliseconds) |
|---|---|
| **Runs Evaluated** | 1000 |
| **Median (p50)** | 5.928 ms |
| **95th Percentile (p95)** | 8.773 ms |
| **Maximum Latency** | 18.131 ms |
| **Mean Latency** | 6.358 ms |
| **Minimum Latency** | 5.249 ms |

---

## 3. Token Creation Latency (`create_token`)

Measures Ed25519 digital signature generation, JSON encoding, and Base64URL string formatting on the token issuer service.

| Metric | Latency (milliseconds) |
|---|---|
| **Median (p50)** | 0.045 ms |
| **95th Percentile (p95)** | 0.066 ms |
| **Maximum Latency** | 0.446 ms |
| **Mean Latency** | 0.048 ms |
| **Minimum Latency** | 0.042 ms |

---

## 4. Engineering & Presentation Notes

1. **Pure Asymmetric Math**: Verification relies strictly on the Ed25519 public key. There is zero symmetric secret sharing and no network RPC to the token issuer at checkout time.
2. **Atomic Replay Prevention**: The SQLite primary-key constraint on `used_nonces` means concurrent attempts with the same nonce result in one success.
3. **PROTOTYPE LIMITATION**: In a globally distributed high-throughput store, SQLite would be replaced by Redis with Lua scripting or a distributed relational database (e.g., PostgreSQL with row-level locking) for cross-datacenter nonce de-duplication.
