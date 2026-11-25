"""Tests for the benchmark regression threshold comparison."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import benchmark  # noqa: E402


def baseline(**overrides) -> dict:
    data = {
        "schema_version": 1,
        "runner": "ubuntu-latest",
        "target": "examples/vulnerable-contract",
        "metric": "median_ms",
        "baseline_median_ms": 100.0,
        "threshold_factor": 3.0,
    }
    data.update(overrides)
    return data


class SummarizeTests(unittest.TestCase):
    def test_statistics_are_deterministic(self):
        stats = benchmark.summarize_samples([30.0, 10.0, 20.0])
        self.assertEqual(stats["min_ms"], 10.0)
        self.assertEqual(stats["median_ms"], 20.0)
        self.assertEqual(stats["max_ms"], 30.0)
        self.assertEqual(stats["runs"], 3)
        self.assertIn("p95_ms", stats)
        self.assertEqual(stats["p95_ms"], 30.0)

    def test_project_size_targets_exist(self):
        self.assertEqual(len(benchmark.PROJECT_SIZE_TARGETS), 3)
        sizes = [s for s, _ in benchmark.PROJECT_SIZE_TARGETS]
        self.assertEqual(sizes, ["small", "medium", "large"])
        for size, target_rel in benchmark.PROJECT_SIZE_TARGETS:
            self.assertTrue((benchmark.ROOT / target_rel).exists(), f"{size} target {target_rel} exists")


class RegressionTests(unittest.TestCase):
    def test_faster_result_passes(self):
        self.assertEqual(
            benchmark.regression_errors({"median_ms": 50.0}, baseline()), []
        )

    def test_result_exactly_at_the_limit_passes(self):
        # baseline 100 ms x 3 = 300 ms; equality is not a regression.
        self.assertEqual(
            benchmark.regression_errors({"median_ms": 300.0}, baseline()), []
        )

    def test_result_beyond_the_limit_fails_with_details(self):
        errors = benchmark.regression_errors({"median_ms": 301.0}, baseline())
        self.assertEqual(len(errors), 1)
        self.assertIn("benchmark regression", errors[0])
        self.assertIn("301.0 ms", errors[0])
        self.assertIn("300.0 ms", errors[0])

    def test_cli_override_factor_is_honoured(self):
        self.assertEqual(
            benchmark.regression_errors(
                {"median_ms": 350.0}, baseline(), factor=5.0
            ),
            [],
        )
        self.assertEqual(
            len(benchmark.regression_errors({"median_ms": 350.0}, baseline(), 2.0)),
            1,
        )

    def test_invalid_factor_is_rejected(self):
        with self.assertRaises(ValueError):
            benchmark.regression_errors({"median_ms": 1.0}, baseline(), factor=1.0)


class BaselineFileTests(unittest.TestCase):
    def test_repository_baseline_is_valid(self):
        data = benchmark.load_baseline(benchmark.DEFAULT_BASELINE)
        self.assertEqual(data["metric"], "median_ms")
        self.assertGreater(data["baseline_median_ms"], 0)
        self.assertGreater(data["threshold_factor"], 1.0)
        self.assertEqual(data["runner"], "ubuntu-latest")

    def test_unknown_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps(baseline(schema_version=99)), encoding="utf-8")
            with self.assertRaises(ValueError):
                benchmark.load_baseline(path)


if __name__ == "__main__":
    unittest.main()
