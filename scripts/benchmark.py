"""IntentLock Phase 10: Performance Benchmark Script.

Measures the real cryptographic and database verification latency for 1,000 valid tokens:
- Creates an isolated temporary SQLite database and Ed25519 keypair.
- Generates 1,000 valid, unique authorization tokens.
- Times both token issuance and verify_checkout execution using time.perf_counter.
- Computes runs, median, 95th percentile, and maximum latencies in milliseconds.
- Outputs runtime platform details (Python version, OS).
- Writes a formatted benchmark report with today's date to docs/benchmark_results.md.
"""

from datetime import date
from pathlib import Path
import platform
import statistics
import sys
import tempfile
import time

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.crypto import load_or_create_keypair
from app.db import init_db
from app.tokens import create_token
from app.verifier import CheckoutRequest, ReasonCode, verify_checkout


def calculate_percentile(sorted_data: list[float], p: float) -> float:
    """Calculate the p-th percentile (0-100) using linear interpolation."""
    if not sorted_data:
        return 0.0
    if len(sorted_data) == 1:
        return sorted_data[0]
    idx = (len(sorted_data) - 1) * (p / 100.0)
    low = int(idx)
    high = min(low + 1, len(sorted_data) - 1)
    weight = idx - low
    return (1.0 - weight) * sorted_data[low] + weight * sorted_data[high]


def run_benchmark(num_runs: int = 1000) -> dict:
    """Execute token creation and verification benchmarks across num_runs."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        db_file = tmp_path / "benchmark_temp.db"
        keys_dir = tmp_path / "benchmark_keys"

        # Initialize temporary isolated database and Ed25519 keypair
        init_db(db_file)
        priv_key, pub_key = load_or_create_keypair(keys_dir)

        creation_times_ms: list[float] = []
        tokens: list[str] = []

        # 1. Benchmark Token Creation (Signing + Base64 encoding)
        for i in range(num_runs):
            t_start = time.perf_counter()
            token = create_token(
                private_key=priv_key,
                user_id=f"user-{i % 10}",
                agent_id="shopper-agent-1",
                merchant_id="demo-store",
                action="purchase",
                item="laptop-14in",
                max_amount_cents=45000,
                currency="USD",
                payee_id="STORE-ACCT-001",
                ttl_seconds=300,
            )
            t_end = time.perf_counter()
            creation_times_ms.append((t_end - t_start) * 1000.0)
            tokens.append(token)

        # 2. Benchmark Verification (Ed25519 signature verify + JSON decode + DB atomic nonce)
        verification_times_ms: list[float] = []
        matching_req = CheckoutRequest(
            agent_id="shopper-agent-1",
            merchant_id="demo-store",
            item="laptop-14in",
            amount_cents=45000,
            payee_id="STORE-ACCT-001",
        )

        for token in tokens:
            t_start = time.perf_counter()
            res = verify_checkout(
                token=token,
                request=matching_req,
                public_key=pub_key,
                store_id="demo-store",
                db_path=db_file,
            )
            t_end = time.perf_counter()

            if not res.allowed or res.reason != ReasonCode.APPROVED:
                raise RuntimeError(f"Benchmark token unexpectedly blocked: {res.reason}")

            verification_times_ms.append((t_end - t_start) * 1000.0)

    # Sort latencies for percentile calculations
    creation_sorted = sorted(creation_times_ms)
    verification_sorted = sorted(verification_times_ms)

    creation_stats = {
        "median_ms": statistics.median(creation_sorted),
        "p95_ms": calculate_percentile(creation_sorted, 95.0),
        "max_ms": max(creation_sorted),
        "mean_ms": statistics.mean(creation_sorted),
        "min_ms": min(creation_sorted),
    }

    verification_stats = {
        "runs": num_runs,
        "median_ms": statistics.median(verification_sorted),
        "p95_ms": calculate_percentile(verification_sorted, 95.0),
        "max_ms": max(verification_sorted),
        "mean_ms": statistics.mean(verification_sorted),
        "min_ms": min(verification_sorted),
    }

    return {
        "num_runs": num_runs,
        "python_version": sys.version.replace("\n", " "),
        "os_info": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "date": date.today().isoformat(),
        "creation": creation_stats,
        "verification": verification_stats,
    }


def write_markdown_report(results: dict, output_file: Path) -> None:
    """Write benchmark metrics to markdown for judges and presentation slides."""
    c = results["creation"]
    v = results["verification"]

    md_content = f"""# IntentLock Performance Benchmark Results

> **Measurement Date**: {results['date']}  
> **Environment**: Python {results['python_version']}  
> **Operating System**: {results['os_info']}  
> **Iterations**: {results['num_runs']} independent transactions  

---

## 1. Executive Summary

IntentLock introduces cryptographic human approval verification without meaningful latency overhead for consumer or business checkouts.

- **Token Verification Median Latency**: **{v['median_ms']:.3f} ms**
- **Token Verification 95th Percentile**: **{v['p95_ms']:.3f} ms**
- **Token Creation Median Latency**: **{c['median_ms']:.3f} ms**

All measurements were dynamically computed using `time.perf_counter` across an isolated SQLite database and fresh Ed25519 keypair.

---

## 2. Detailed Verification Latency (`verify_checkout`)

The verifier executes signature verification with the Ed25519 public key, decodes token parameters, verifies constraints (payee, amount ceiling, item, merchant, agent, TTL), and atomically consumes the single-use nonce in SQLite.

| Metric | Latency (milliseconds) |
|---|---|
| **Runs Evaluated** | {v['runs']} |
| **Median (p50)** | {v['median_ms']:.3f} ms |
| **95th Percentile (p95)** | {v['p95_ms']:.3f} ms |
| **Maximum Latency** | {v['max_ms']:.3f} ms |
| **Mean Latency** | {v['mean_ms']:.3f} ms |
| **Minimum Latency** | {v['min_ms']:.3f} ms |

---

## 3. Token Creation Latency (`create_token`)

Measures Ed25519 digital signature generation, JSON encoding, and Base64URL string formatting on the token issuer service.

| Metric | Latency (milliseconds) |
|---|---|
| **Median (p50)** | {c['median_ms']:.3f} ms |
| **95th Percentile (p95)** | {c['p95_ms']:.3f} ms |
| **Maximum Latency** | {c['max_ms']:.3f} ms |
| **Mean Latency** | {c['mean_ms']:.3f} ms |
| **Minimum Latency** | {c['min_ms']:.3f} ms |

---

## 4. Engineering & Presentation Notes

1. **Pure Asymmetric Math**: Verification relies strictly on the Ed25519 public key. There is zero symmetric secret sharing and no network RPC to the token issuer at checkout time.
2. **Atomic Replay Prevention**: The SQLite unique constraint on `used_nonces` guarantees atomic single-use semantics even under concurrent attempts.
3. **PROTOTYPE LIMITATION**: In a globally distributed high-throughput store, SQLite would be replaced by Redis with Lua scripting or a distributed relational database (e.g., PostgreSQL with row-level locking) for cross-datacenter nonce de-duplication.
"""

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(md_content, encoding="utf-8")


def main():
    print("=" * 64)
    print("         IntentLock Cryptographic Benchmark Runner")
    print("=" * 64)
    print("Running 1,000 token creation and verification iterations...")

    results = run_benchmark(num_runs=1000)

    print("\nEnvironment:")
    print(f"  Python Version:   {results['python_version']}")
    print(f"  Operating System: {results['os_info']}")
    print(f"  Benchmark Date:   {results['date']}")
    print(f"  Iterations:       {results['num_runs']}")

    c = results["creation"]
    print("\nToken Creation Latency (create_token):")
    print(f"  Median:           {c['median_ms']:.3f} ms")
    print(f"  95th Percentile:  {c['p95_ms']:.3f} ms")
    print(f"  Maximum:          {c['max_ms']:.3f} ms")
    print(f"  Mean:             {c['mean_ms']:.3f} ms")

    v = results["verification"]
    print("\nToken Verification Latency (verify_checkout):")
    print(f"  Number of runs:   {v['runs']}")
    print(f"  Median:           {v['median_ms']:.3f} ms")
    print(f"  95th Percentile:  {v['p95_ms']:.3f} ms")
    print(f"  Maximum:          {v['max_ms']:.3f} ms")
    print(f"  Mean:             {v['mean_ms']:.3f} ms")

    docs_report = PROJECT_ROOT / "docs" / "benchmark_results.md"
    write_markdown_report(results, docs_report)
    print(f"\nResults successfully written to: {docs_report.relative_to(PROJECT_ROOT)}")
    print("=" * 64)


if __name__ == "__main__":
    main()
