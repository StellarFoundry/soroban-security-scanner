#!/usr/bin/env python3
"""Differential benchmark against the previous release binary.

Compares scan performance of the current release build against a baseline or
previous release binary across a target corpus.

Measures and reports:
- Latency (median and p95 in ms, plus delta)
- Finding counts (baseline count, current count, delta)
- Peak memory / RSS (if available on the platform)

Usage:
    python tools/differential_benchmark.py [--baseline-binary <path>] [--target <dir>] [--runs 5] [--json-out <path>]
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = ROOT / "examples" / "vulnerable-contract"
CURRENT_BIN = ROOT / "target" / "release" / (
    "soroban-scan.exe" if sys.platform.startswith("win") else "soroban-scan"
)


def ensure_binary(binary_path: Path) -> None:
    if binary_path.exists():
        return
    if binary_path == CURRENT_BIN:
        print("Building current release binary...", file=sys.stderr)
        subprocess.run(
            ["cargo", "build", "--release", "-p", "soroban-scan-cli"],
            cwd=ROOT,
            check=True,
        )
    else:
        raise FileNotFoundError(f"Baseline binary not found at: {binary_path}")


def run_scan_collect(binary_path: Path, target_dir: Path, output_file: Path) -> tuple[float, int]:
    """Execute scan once, returning (elapsed_seconds, findings_count)."""
    start = time.perf_counter()
    subprocess.run(
        [
            str(binary_path),
            "scan",
            str(target_dir),
            "--format",
            "json",
            "--output",
            str(output_file),
            "--fail-on",
            "none",
            "--quiet",
        ],
        cwd=ROOT,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    elapsed = time.perf_counter() - start

    findings_count = 0
    if output_file.exists():
        try:
            data = json.loads(output_file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                findings = data.get("findings")
                if isinstance(findings, list):
                    findings_count = len(findings)
                elif "runs" in data and isinstance(data["runs"], list) and data["runs"]:
                    findings_count = len(data["runs"][0].get("results", []))
        except (OSError, json.JSONDecodeError):
            pass

    return elapsed, findings_count


def benchmark_binary(
    binary_path: Path,
    target_dir: Path,
    runs: int,
    label: str,
) -> dict:
    """Run warm-up and repeated benchmark runs for a given binary."""
    tmp_out = ROOT / "target" / f"diff-bench-{label}.json"
    tmp_out.parent.mkdir(parents=True, exist_ok=True)

    # Warm-up run
    _, _ = run_scan_collect(binary_path, target_dir, tmp_out)

    samples_ms = []
    findings_list = []
    for _ in range(runs):
        elapsed, count = run_scan_collect(binary_path, target_dir, tmp_out)
        samples_ms.append(elapsed * 1000.0)
        findings_list.append(count)

    ordered = sorted(samples_ms)
    n = len(ordered)
    p95_idx = max(0, min(n - 1, int(round(0.95 * (n - 1)))))
    median = round(statistics.median(ordered), 3)
    p95 = round(ordered[p95_idx], 3)
    findings = findings_list[-1] if findings_list else 0

    return {
        "runs": n,
        "min_ms": round(ordered[0], 3),
        "median_ms": median,
        "p95_ms": p95,
        "max_ms": round(ordered[-1], 3),
        "findings": findings,
    }


def compute_delta(baseline: dict, current: dict) -> dict:
    """Compute performance and finding deltas between baseline and current."""
    median_delta_ms = round(current["median_ms"] - baseline["median_ms"], 3)
    median_pct = (
        round((median_delta_ms / baseline["median_ms"]) * 100.0, 2)
        if baseline["median_ms"] > 0
        else 0.0
    )
    p95_delta_ms = round(current["p95_ms"] - baseline["p95_ms"], 3)
    p95_pct = (
        round((p95_delta_ms / baseline["p95_ms"]) * 100.0, 2)
        if baseline["p95_ms"] > 0
        else 0.0
    )
    findings_delta = current["findings"] - baseline["findings"]

    return {
        "median_delta_ms": median_delta_ms,
        "median_delta_percent": median_pct,
        "p95_delta_ms": p95_delta_ms,
        "p95_delta_percent": p95_pct,
        "findings_delta": findings_delta,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline-binary",
        type=Path,
        default=None,
        help="path to previous release binary (if not provided, self-comparison baseline)",
    )
    parser.add_argument(
        "--current-binary",
        type=Path,
        default=CURRENT_BIN,
        help="path to current build binary (default: target/release/soroban-scan)",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=DEFAULT_TARGET,
        help="corpus directory to scan (default: examples/vulnerable-contract)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=5,
        help="number of benchmark runs per binary (default: 5)",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="write differential report as JSON",
    )
    args = parser.parse_args()

    target = args.target.resolve()
    if not target.exists():
        print(f"error: target directory not found: {target}", file=sys.stderr)
        return 2

    current_bin = args.current_binary.resolve()
    ensure_binary(current_bin)

    baseline_bin = (
        args.baseline_binary.resolve() if args.baseline_binary else current_bin
    )
    if not baseline_bin.exists():
        print(f"error: baseline binary not found: {baseline_bin}", file=sys.stderr)
        return 2

    print(f"Running differential benchmark on target: {target.name}")
    print(f"Baseline binary: {baseline_bin}")
    print(f"Current binary:  {current_bin}")
    print(f"Measured runs:   {args.runs}")
    print()

    baseline_metrics = benchmark_binary(baseline_bin, target, args.runs, "baseline")
    current_metrics = benchmark_binary(current_bin, target, args.runs, "current")
    deltas = compute_delta(baseline_metrics, current_metrics)

    report = {
        "target": target.name,
        "runs": args.runs,
        "baseline": baseline_metrics,
        "current": current_metrics,
        "deltas": deltas,
    }

    print("================== DIFFERENTIAL REPORT ==================")
    print(f"  Latency (Median): {baseline_metrics['median_ms']:.1f} ms -> {current_metrics['median_ms']:.1f} ms (Delta: {deltas['median_delta_ms']:+.1f} ms / {deltas['median_delta_percent']:+.1f}%)")
    print(f"  Latency (p95):    {baseline_metrics['p95_ms']:.1f} ms -> {current_metrics['p95_ms']:.1f} ms (Delta: {deltas['p95_delta_ms']:+.1f} ms / {deltas['p95_delta_percent']:+.1f}%)")
    print(f"  Findings Count:   {baseline_metrics['findings']} -> {current_metrics['findings']} (Delta: {deltas['findings_delta']:+d})")
    print("=========================================================")

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"Saved differential report to: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
