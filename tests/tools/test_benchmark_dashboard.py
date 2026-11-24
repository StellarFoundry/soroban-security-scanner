"""Tests for the benchmark dashboard artifact and its CI validator."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import benchmark  # noqa: E402
import check_benchmark_artifact  # noqa: E402


def stats(**overrides) -> dict:
    data = {
        "runs": 5,
        "min_ms": 100.0,
        "median_ms": 120.0,
        "mean_ms": 125.0,
        "max_ms": 160.0,
    }
    data.update(overrides)
    return data


def baseline(**overrides) -> dict:
    data = {
        "schema_version": 1,
        "runner": "ubuntu-latest",
        "target": "examples/vulnerable-contract",
        "metric": "median_ms",
        "baseline_median_ms": 250.0,
        "threshold_factor": 6.0,
    }
    data.update(overrides)
    return data


def payload(**overrides) -> dict:
    data = benchmark.dashboard_payload(
        stats=stats(),
        baseline=baseline(),
        target_label="examples/vulnerable-contract",
        limit_ms=1500.0,
        factor=6.0,
        errors=[],
    )
    data.update(overrides)
    return data


class TargetLabelTests(unittest.TestCase):
    def test_relative_target_is_recorded_without_an_absolute_path(self) -> None:
        label = benchmark.relative_target_label(
            benchmark.ROOT / "examples" / "vulnerable-contract"
        )
        self.assertEqual(label, "examples/vulnerable-contract")
        self.assertFalse(Path(label).is_absolute())

    def test_target_outside_the_repository_falls_back_to_its_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            label = benchmark.relative_target_label(Path(tmp), benchmark.ROOT)
        self.assertEqual(label, Path(tmp).name)
        self.assertNotIn(tmp, label)
        self.assertFalse(Path(label).is_absolute())


class DashboardPayloadTests(unittest.TestCase):
    def test_payload_records_the_run_and_comparison(self) -> None:
        data = payload()
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["metric"], "median_ms")
        self.assertEqual(data["target"], "examples/vulnerable-contract")
        self.assertEqual(data["runner"], "ubuntu-latest")
        self.assertEqual(data["status"], "pass")
        self.assertEqual(data["stats"]["median_ms"], 120.0)
        self.assertEqual(data["baseline"]["limit_ms"], 1500.0)
        self.assertEqual(data["regressions"], [])

    def test_failing_run_records_regressions(self) -> None:
        errors = ["benchmark regression: median 1600.0 ms exceeds 1500.0 ms"]
        data = payload(status="fail", regressions=errors)
        self.assertEqual(data["status"], "fail")
        self.assertEqual(data["regressions"], errors)

    def test_payload_contains_no_absolute_paths(self) -> None:
        serialized = json.dumps(payload())
        self.assertNotIn(str(benchmark.ROOT), serialized)
        self.assertNotIn(str(Path.home()), serialized)


class RenderHtmlTests(unittest.TestCase):
    def test_html_is_self_contained(self) -> None:
        markup = benchmark.render_html(payload())
        self.assertIn("<!DOCTYPE html>", markup)
        self.assertNotIn("<script", markup.lower())
        self.assertNotIn("http://", markup)
        self.assertNotIn("https://", markup)
        self.assertNotIn("src=", markup.lower())

    def test_html_shows_the_measurements(self) -> None:
        markup = benchmark.render_html(payload())
        self.assertIn("Benchmark dashboard", markup)
        self.assertIn("examples/vulnerable-contract", markup)
        self.assertIn("120.0 ms", markup)
        self.assertIn("1500.0 ms", markup)
        self.assertIn("Within threshold", markup)

    def test_html_reports_regressions(self) -> None:
        markup = benchmark.render_html(
            payload(status="fail", regressions=["median 1600.0 ms exceeds 1500.0 ms"])
        )
        self.assertIn("Regression detected", markup)
        self.assertIn("median 1600.0 ms exceeds 1500.0 ms", markup)

    def test_html_escapes_injected_labels(self) -> None:
        markup = benchmark.render_html(
            payload(target='<img src="x" onerror="alert(1)">')
        )
        self.assertNotIn("<img", markup)
        self.assertIn("&lt;img", markup)

    def test_html_contains_no_absolute_paths(self) -> None:
        markup = benchmark.render_html(payload())
        self.assertNotIn(str(benchmark.ROOT), markup)
        self.assertNotIn(str(Path.home()), markup)


class WriteDashboardTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self._tmp.name) / "dashboard"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_writes_both_artifacts(self) -> None:
        json_path, html_path = benchmark.write_dashboard(
            self.directory, payload()
        )
        self.assertTrue(json_path.is_file())
        self.assertTrue(html_path.is_file())
        self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["status"], "pass")
        self.assertIn("<!DOCTYPE html>", html_path.read_text(encoding="utf-8"))

    def test_written_artifact_passes_the_validator(self) -> None:
        benchmark.write_dashboard(self.directory, payload())
        self.assertEqual(check_benchmark_artifact.check(self.directory), [])


class CheckArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self._tmp.name)
        benchmark.write_dashboard(self.directory, payload())

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_valid_artifact_passes(self) -> None:
        self.assertEqual(check_benchmark_artifact.check(self.directory), [])

    def test_missing_files_are_reported(self) -> None:
        (self.directory / benchmark.ARTIFACT_HTML).unlink()
        problems = check_benchmark_artifact.check(self.directory)
        self.assertTrue(any("index.html" in problem for problem in problems))

    def test_malformed_json_is_reported(self) -> None:
        (self.directory / benchmark.ARTIFACT_JSON).write_text("{", encoding="utf-8")
        problems = check_benchmark_artifact.check(self.directory)
        self.assertTrue(any("cannot be parsed" in problem for problem in problems))

    def test_external_script_is_rejected(self) -> None:
        path = self.directory / benchmark.ARTIFACT_HTML
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "</body>", "<script src=\"https://example.com/x.js\"></script></body>"
            ),
            encoding="utf-8",
        )
        problems = check_benchmark_artifact.check(self.directory)
        self.assertTrue(any("scripts are not allowed" in problem for problem in problems))
        self.assertTrue(
            any("external resources are not allowed" in problem for problem in problems)
        )

    def test_absolute_path_in_json_is_rejected(self) -> None:
        path = self.directory / benchmark.ARTIFACT_JSON
        data = json.loads(path.read_text(encoding="utf-8"))
        data["target"] = "/home/runner/work/contract"
        path.write_text(json.dumps(data), encoding="utf-8")
        problems = check_benchmark_artifact.check(self.directory)
        self.assertTrue(any("repository-relative" in problem for problem in problems))
        self.assertTrue(any("absolute path in artifact" in problem for problem in problems))

    def test_absolute_path_in_html_is_rejected(self) -> None:
        path = self.directory / benchmark.ARTIFACT_HTML
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "</body>", "<p>/Users/someone/project</p></body>"
            ),
            encoding="utf-8",
        )
        problems = check_benchmark_artifact.check(self.directory)
        self.assertTrue(any("absolute path in artifact" in problem for problem in problems))

    def test_inconsistent_failing_run_is_rejected(self) -> None:
        path = self.directory / benchmark.ARTIFACT_JSON
        data = json.loads(path.read_text(encoding="utf-8"))
        data["status"] = "fail"
        path.write_text(json.dumps(data), encoding="utf-8")
        problems = check_benchmark_artifact.check(self.directory)
        self.assertTrue(
            any("must record at least one regression" in problem for problem in problems)
        )


if __name__ == "__main__":
    unittest.main()
