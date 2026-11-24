"""Tests for the check-run helper."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import check_run  # noqa: E402


def finding(
    *,
    rule_id: str = "SS-001",
    severity: str = "high",
    line: int = 10,
    file: str = "src/lib.rs",
    title: str = "State-changing entry point without caller authorization",
) -> dict:
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "evidence": "`persistent` storage mutation with no authorization",
        "remediation": "Call `require_auth()` before mutating state.",
        "location": {"file": file, "line": line},
    }


class ConclusionTests(unittest.TestCase):
    def test_high_finding_fails_the_default_threshold(self):
        self.assertEqual(
            check_run.conclusion_for([finding(severity="high")], "high"),
            "failure",
        )

    def test_critical_finding_fails_a_high_threshold(self):
        self.assertEqual(
            check_run.conclusion_for([finding(severity="critical")], "high"),
            "failure",
        )

    def test_medium_finding_passes_a_high_threshold(self):
        self.assertEqual(
            check_run.conclusion_for([finding(severity="medium")], "high"),
            "success",
        )

    def test_medium_finding_fails_a_medium_threshold(self):
        self.assertEqual(
            check_run.conclusion_for([finding(severity="medium")], "medium"),
            "failure",
        )

    def test_none_disables_the_gate(self):
        self.assertEqual(
            check_run.conclusion_for([finding(severity="critical")], "none"),
            "success",
        )

    def test_no_findings_passes(self):
        self.assertEqual(check_run.conclusion_for([], "high"), "success")


class PayloadTests(unittest.TestCase):
    def test_payload_has_completed_status_and_annotations(self):
        report = {"findings": [finding(line=23)]}
        payload = check_run.build_payload(
            report,
            name="Soroban Security Scan",
            head_sha="abc123",
            fail_on="high",
        )
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["conclusion"], "failure")
        self.assertEqual(payload["head_sha"], "abc123")
        self.assertEqual(payload["name"], "Soroban Security Scan")
        annotations = payload["output"]["annotations"]
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]["path"], "src/lib.rs")
        self.assertEqual(annotations[0]["start_line"], 23)
        self.assertEqual(annotations[0]["annotation_level"], "failure")
        self.assertIn("SS-001", annotations[0]["message"])
        self.assertIn("require_auth", annotations[0]["raw_details"])

    def test_annotations_are_capped_at_the_github_limit(self):
        findings = [finding(line=index + 1) for index in range(55)]
        payload = check_run.build_payload(
            {"findings": findings},
            name="Soroban Security Scan",
            head_sha="abc123",
            max_annotations=check_run.GITHUB_ANNOTATION_LIMIT,
        )
        annotations = payload["output"]["annotations"]
        self.assertEqual(len(annotations), check_run.GITHUB_ANNOTATION_LIMIT)
        self.assertIn("5 finding(s) were not annotated", payload["output"]["summary"])

    def test_annotation_levels_follow_severity(self):
        levels = {
            "critical": "failure",
            "high": "failure",
            "medium": "warning",
            "low": "notice",
            "info": "notice",
        }
        for severity, level in levels.items():
            with self.subTest(severity=severity):
                self.assertEqual(
                    check_run.annotation_for(finding(severity=severity))[
                        "annotation_level"
                    ],
                    level,
                )

    def test_windows_paths_are_normalized(self):
        annotation = check_run.annotation_for(finding(file="src\\contracts\\lib.rs"))
        self.assertEqual(annotation["path"], "src/contracts/lib.rs")

    def test_empty_report_is_a_success_with_no_annotations(self):
        payload = check_run.build_payload(
            {"findings": []},
            name="Soroban Security Scan",
            head_sha="abc123",
        )
        self.assertEqual(payload["conclusion"], "success")
        self.assertEqual(payload["output"]["annotations"], [])
        self.assertEqual(payload["output"]["title"], "No security findings")

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            check_run.build_payload(
                {"findings": []},
                name="Soroban Security Scan",
                head_sha="abc123",
                fail_on="urgent",
            )

    def test_annotation_limit_above_github_limit_is_rejected(self):
        with self.assertRaises(ValueError):
            check_run.build_payload(
                {"findings": []},
                name="Soroban Security Scan",
                head_sha="abc123",
                max_annotations=check_run.GITHUB_ANNOTATION_LIMIT + 1,
            )

    def test_report_must_contain_findings_array(self):
        with self.assertRaises(ValueError):
            check_run.build_payload(
                {},
                name="Soroban Security Scan",
                head_sha="abc123",
            )


def gate(conclusion: str, **overrides) -> dict:
    record = {
        "schema_version": 1,
        "conclusion": conclusion,
        "title": f"Policy gate {conclusion}",
        "summary": f"**Policy gate {conclusion}**\n\n[Full scan report](https://example.test/report)",
        "threshold": "high",
        "gated": 1,
        "blocking": 1 if conclusion == "failure" else 0,
        "suppressed": 0,
        "baseline_accepted": 0,
        "expired_waivers": 0,
    }
    record.update(overrides)
    return record


class StatusGateTests(unittest.TestCase):
    def payload(self, record, findings=None):
        return check_run.build_payload(
            {"findings": findings if findings is not None else [finding()]},
            name="Soroban Security Gate",
            head_sha="abc123",
            gate=record,
        )

    def test_failure_gate_sets_a_failure_conclusion(self):
        payload = self.payload(gate("failure"))
        self.assertEqual(payload["conclusion"], "failure")
        self.assertEqual(payload["output"]["title"], "Policy gate failure")

    def test_success_gate_overrides_the_local_threshold(self):
        # A high finding would fail the default threshold, but the scanner's
        # policy gate (for example a baselined finding) says success.
        payload = self.payload(gate("success"))
        self.assertEqual(payload["conclusion"], "success")

    def test_neutral_gate_is_published_as_neutral(self):
        payload = self.payload(gate("neutral"), findings=[])
        self.assertEqual(payload["conclusion"], "neutral")
        self.assertEqual(payload["output"]["annotations"], [])

    def test_summary_keeps_the_report_link_and_notes_annotations(self):
        summary = self.payload(gate("failure"))["output"]["summary"]
        self.assertIn("[Full scan report](https://example.test/report)", summary)
        self.assertIn("Annotated 1 finding(s) inline.", summary)

    def test_long_titles_are_truncated_to_the_github_limit(self):
        payload = self.payload(gate("failure", title="x" * 400))
        self.assertEqual(len(payload["output"]["title"]), check_run.TITLE_LIMIT)

    def test_invalid_gate_records_are_rejected(self):
        for record in (
            gate("maybe"),
            gate("success", schema_version=2),
            gate("success", title=""),
            gate("success", summary=None),
        ):
            with self.assertRaises(ValueError):
                self.payload(record)

    def test_cli_reads_the_gate_file(self):
        import contextlib
        import io
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            gate_file = Path(directory) / "gate.json"
            report.write_text(json.dumps({"findings": [finding()]}), encoding="utf-8")
            gate_file.write_text(json.dumps(gate("neutral")), encoding="utf-8")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = check_run.main(
                    [
                        "--report",
                        str(report),
                        "--gate",
                        str(gate_file),
                        "--repo",
                        "owner/repo",
                        "--head-sha",
                        "abc123",
                        "--dry-run",
                    ]
                )
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["conclusion"], "neutral")


class CreateCheckRunTests(unittest.TestCase):
    def test_posts_the_payload_through_gh_api(self):
        calls = []

        def fake_runner(arguments, payload=None):
            calls.append((list(arguments), payload))
            return json.dumps({"id": 123, "html_url": "https://example.test/check"})

        report = {"findings": [finding()]}
        payload = check_run.build_payload(
            report,
            name="Soroban Security Scan",
            head_sha="abc123",
        )
        created = check_run.create_check_run("owner/repo", payload, runner=fake_runner)
        self.assertEqual(created["id"], 123)
        self.assertIn("--method", calls[0][0])
        self.assertEqual(calls[0][1], payload)


if __name__ == "__main__":
    unittest.main()
