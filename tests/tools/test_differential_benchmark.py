"""Tests for differential benchmark comparisons."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import differential_benchmark  # noqa: E402


class DifferentialBenchmarkTests(unittest.TestCase):
    def test_compute_delta_identical(self):
        metrics = {
            "runs": 5,
            "min_ms": 10.0,
            "median_ms": 20.0,
            "p95_ms": 25.0,
            "max_ms": 30.0,
            "findings": 4,
        }
        delta = differential_benchmark.compute_delta(metrics, metrics)
        self.assertEqual(delta["median_delta_ms"], 0.0)
        self.assertEqual(delta["median_delta_percent"], 0.0)
        self.assertEqual(delta["p95_delta_ms"], 0.0)
        self.assertEqual(delta["p95_delta_percent"], 0.0)
        self.assertEqual(delta["findings_delta"], 0)

    def test_compute_delta_regression(self):
        baseline = {
            "median_ms": 100.0,
            "p95_ms": 120.0,
            "findings": 5,
        }
        current = {
            "median_ms": 120.0,
            "p95_ms": 150.0,
            "findings": 7,
        }
        delta = differential_benchmark.compute_delta(baseline, current)
        self.assertEqual(delta["median_delta_ms"], 20.0)
        self.assertEqual(delta["median_delta_percent"], 20.0)
        self.assertEqual(delta["p95_delta_ms"], 30.0)
        self.assertEqual(delta["p95_delta_percent"], 25.0)
        self.assertEqual(delta["findings_delta"], 2)


if __name__ == "__main__":
    unittest.main()
