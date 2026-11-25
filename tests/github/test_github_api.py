"""Offline tests for the GitHub API request surface.

A deterministic in-memory mock stands in for ``gh api``. It asserts endpoints,
methods, and request bodies, and no test uses a token or network access.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import github_api  # noqa: E402


class MockGitHub:
    """Routes ``gh api`` calls to a deterministic in-memory GitHub."""

    def __init__(self):
        self.calls = []
        self.next_comment_id = 100

    def __call__(self, arguments, payload=None):
        arguments = list(arguments)
        self.calls.append((arguments, payload))
        method = "GET"
        if "--method" in arguments:
            method = arguments[arguments.index("--method") + 1]
        endpoint = arguments[-1]

        if method == "GET" and endpoint == "repos/owner/repo/installation":
            return json.dumps({"id": 7, "account": {"login": "owner"}})

        if method == "GET" and endpoint.startswith(
            "repos/owner/repo/issues/42/comments"
        ):
            return json.dumps(
                [
                    [{"id": 1, "body": "first"}],
                    [{"id": 2, "body": "second"}],
                ]
            )

        if method == "POST" and endpoint == "repos/owner/repo/issues/42/comments":
            self.next_comment_id += 1
            return json.dumps({"id": self.next_comment_id, "body": payload["body"]})

        if method == "PATCH" and endpoint.startswith("repos/owner/repo/issues/comments/"):
            return json.dumps({"id": int(endpoint.rsplit("/", 1)[-1]), "body": payload["body"]})

        if method == "DELETE" and endpoint.startswith(
            "repos/owner/repo/issues/comments/"
        ):
            return ""

        if method == "POST" and endpoint == "repos/owner/repo/check-runs":
            return json.dumps({"id": 99, "html_url": "https://example.test/check"})

        raise AssertionError(f"unexpected gh api call: {method} {endpoint}")

    def last(self):
        return self.calls[-1]


class InstallationTests(unittest.TestCase):
    def test_reads_the_repository_installation(self):
        mock_github = MockGitHub()
        installation = github_api.get_installation("owner/repo", runner=mock_github)
        self.assertEqual(installation["id"], 7)
        self.assertEqual(
            mock_github.last()[0], ["repos/owner/repo/installation"]
        )

    def test_rejects_a_non_object_response(self):
        with self.assertRaises(github_api.GitHubApiError):
            github_api.get_installation(
                "owner/repo", runner=lambda *args, **kwargs: "[]"
            )

    def test_reads_only_the_validated_installation_id(self):
        mock_github = MockGitHub()
        identifier = github_api.get_installation_id("owner/repo", runner=mock_github)
        self.assertEqual(identifier, 7)
        self.assertEqual(mock_github.last()[0], ["repos/owner/repo/installation"])

    def test_discards_credentials_from_the_installation_response(self):
        def runner(*args, **kwargs):
            return json.dumps(
                {"id": 42, "token": "must-not-persist", "account": {"login": "owner"}}
            )

        self.assertEqual(
            github_api.get_installation_id("owner/repo", runner=runner), 42
        )

    def test_rejects_invalid_installation_ids(self):
        for value in ("7", True, 0, -1, 2**63):
            with self.subTest(value=value):
                with self.assertRaises(github_api.InvalidInstallationError):
                    github_api.installation_id({"id": value})
        for response in ({}, [], "7", None):
            with self.subTest(response=response):
                with self.assertRaises(github_api.InvalidInstallationError):
                    github_api.installation_id(response)

    def test_rejects_untrusted_repository_names(self):
        invalid = (
            "",
            "owner",
            "owner/repo/branch",
            "owner/repo?x=1",
            "owner/repo\ninjected",
            "a" * 201 + "/repo",
            7,
        )
        for repo in invalid:
            with self.subTest(repo=repo):
                with self.assertRaises(github_api.GitHubApiError):
                    github_api.get_installation_id(
                        repo, runner=lambda *args, **kwargs: "{}"
                    )


class CheckRunTests(unittest.TestCase):
    def test_posts_the_exact_request_body(self):
        mock_github = MockGitHub()
        payload = {
            "name": "Soroban Security Scan",
            "head_sha": "abc123",
            "status": "completed",
            "conclusion": "failure",
            "output": {"title": "1 finding", "summary": "summary", "annotations": []},
        }
        created = github_api.create_check_run(
            "owner/repo", payload, runner=mock_github
        )
        self.assertEqual(created["id"], 99)
        arguments, sent = mock_github.last()
        self.assertEqual(
            arguments,
            ["--method", "POST", "--input", "-", "repos/owner/repo/check-runs"],
        )
        self.assertEqual(sent, payload)

    def test_rejects_a_non_object_response(self):
        with self.assertRaises(github_api.GitHubApiError):
            github_api.create_check_run(
                "owner/repo", {"name": "x"}, runner=lambda *args, **kwargs: "null"
            )


class CommentTests(unittest.TestCase):
    def test_lists_every_paginated_comment(self):
        mock_github = MockGitHub()
        comments = github_api.list_comments("owner/repo", 42, runner=mock_github)
        self.assertEqual([comment["id"] for comment in comments], [1, 2])
        self.assertEqual(
            mock_github.last()[0],
            [
                "--paginate",
                "--slurp",
                "repos/owner/repo/issues/42/comments?per_page=100",
            ],
        )

    def test_creates_comment_with_only_the_body(self):
        mock_github = MockGitHub()
        created = github_api.create_comment(
            "owner/repo", 42, "scan summary", runner=mock_github
        )
        self.assertEqual(created["body"], "scan summary")
        arguments, sent = mock_github.last()
        self.assertEqual(
            arguments,
            [
                "--method",
                "POST",
                "--input",
                "-",
                "repos/owner/repo/issues/42/comments",
            ],
        )
        self.assertEqual(sent, {"body": "scan summary"})

    def test_updates_and_deletes_an_existing_comment(self):
        mock_github = MockGitHub()
        updated = github_api.update_comment(
            "owner/repo", 5, "new summary", runner=mock_github
        )
        self.assertEqual(updated["body"], "new summary")
        arguments, sent = mock_github.last()
        self.assertEqual(
            arguments,
            [
                "--method",
                "PATCH",
                "--input",
                "-",
                "repos/owner/repo/issues/comments/5",
            ],
        )
        self.assertEqual(sent, {"body": "new summary"})

        github_api.delete_comment("owner/repo", 5, runner=mock_github)
        self.assertEqual(
            mock_github.last()[0],
            ["--method", "DELETE", "repos/owner/repo/issues/comments/5"],
        )

    def test_malformed_comment_responses_are_errors(self):
        with self.assertRaises(github_api.GitHubApiError):
            github_api.create_comment(
                "owner/repo", 42, "body", runner=lambda *args, **kwargs: "[]"
            )
        with self.assertRaises(github_api.GitHubApiError):
            github_api.update_comment(
                "owner/repo", 5, "body", runner=lambda *args, **kwargs: "null"
            )

    def test_failures_propagate_without_retrying_writes(self):
        calls = []

        def failing(arguments, payload=None):
            calls.append((list(arguments), payload))
            raise github_api.GitHubApiError("gh api failed with exit code 1: HTTP 403")

        with self.assertRaises(github_api.GitHubApiError):
            github_api.create_comment("owner/repo", 42, "body", runner=failing)
        self.assertEqual(len(calls), 1)


def completed(returncode, stderr="", stdout=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


class RetryTests(unittest.TestCase):
    def run_with(self, responses, arguments, payload=None):
        with mock.patch.object(
            github_api.subprocess, "run", side_effect=responses
        ) as run:
            try:
                return github_api.run_gh(
                    arguments, payload, retry_delay=0
                )
            finally:
                self.run_calls = run.call_count

    def test_read_retries_a_transient_failure(self):
        output = self.run_with(
            [
                completed(1, stderr="gh: HTTP 502: Bad Gateway"),
                completed(0, stdout='{"ok":true}'),
            ],
            ["--paginate", "repos/owner/repo/issues/42/comments"],
        )
        self.assertEqual(output, '{"ok":true}')
        self.assertEqual(self.run_calls, 2)

    def test_read_gives_up_after_the_attempt_budget(self):
        responses = [completed(1, stderr="gh: HTTP 503: Service Unavailable")] * 3
        with self.assertRaises(github_api.GitHubApiError):
            self.run_with(
                responses, ["repos/owner/repo/installation"]
            )
        self.assertEqual(self.run_calls, 3)

    def test_permanent_read_errors_are_not_retried(self):
        with self.assertRaises(github_api.GitHubApiError):
            self.run_with(
                [completed(1, stderr="gh: HTTP 403: Forbidden")],
                ["repos/owner/repo/installation"],
            )
        self.assertEqual(self.run_calls, 1)

    def test_writes_are_never_retried(self):
        with self.assertRaises(github_api.GitHubApiError):
            self.run_with(
                [completed(1, stderr="gh: HTTP 502: Bad Gateway")] * 3,
                [
                    "--method",
                    "POST",
                    "--input",
                    "-",
                    "repos/owner/repo/check-runs",
                ],
                {"name": "x"},
            )
        self.assertEqual(self.run_calls, 1)

    def test_payload_is_sent_as_json_on_stdin(self):
        with mock.patch.object(
            github_api.subprocess,
            "run",
            return_value=completed(0, stdout="{}"),
        ) as run:
            github_api.run_gh(
                ["--method", "POST", "--input", "-", "repos/owner/repo/check-runs"],
                {"name": "Soroban Security Scan"},
            )
        self.assertEqual(
            json.loads(run.call_args.kwargs["input"]),
            {"name": "Soroban Security Scan"},
        )
        self.assertEqual(run.call_args.args[0], ["gh", "api", "--method", "POST", "--input", "-", "repos/owner/repo/check-runs"])


if __name__ == "__main__":
    unittest.main()
