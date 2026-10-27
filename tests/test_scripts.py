"""Tests for Phase 10 benchmark and attack evaluation scripts."""

from pathlib import Path
import pytest
from scripts.benchmark import run_benchmark, write_markdown_report
from scripts.run_attack_suite import run_attack_suite


def test_benchmark_runs_and_returns_metrics():
    """Verify run_benchmark computes valid positive latencies for all percentiles."""
    results = run_benchmark(num_runs=20)
    assert results["num_runs"] == 20
    assert "creation" in results
    assert "verification" in results
    assert results["creation"]["median_ms"] > 0
    assert results["verification"]["median_ms"] > 0
    assert results["verification"]["p95_ms"] >= results["verification"]["median_ms"]
    assert results["verification"]["max_ms"] >= results["verification"]["p95_ms"]


def test_benchmark_report_written_with_date(tmp_path: Path):
    """Verify write_markdown_report generates a complete report with today's date."""
    results = run_benchmark(num_runs=10)
    output_file = tmp_path / "docs" / "test_report.md"
    write_markdown_report(results, output_file)

    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "IntentLock Performance Benchmark Results" in content
    assert results["date"] in content
    assert "verify_checkout" in content


def test_attack_suite_blocks_all_12_attacks():
    """Verify run_attack_suite blocks all 12 attacks and verifies unprotected vulnerability."""
    results, blocked, unprot = run_attack_suite()
    assert len(results) == 12
    assert blocked == 12
    assert unprot == 12

    for r in results:
        assert r["status"] == "PASS"
        assert r["expected"] == r["actual"]
        assert r["unprotected_succeeded"] is True
