"""Tests for GitHub API base URL validation and host selection."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / ".github" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import github_api  # noqa: E402


def env_without_override() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k != github_api.API_URL_ENV}


class ValidateApiBaseUrlTests(unittest.TestCase):
    def test_accepts_and_normalizes_valid_urls(self):
        cases = {
            "https://api.github.com": "https://api.github.com",
            "https://api.github.com/": "https://api.github.com",
            "https://github.example.com/api/v3": "https://github.example.com/api/v3",
            "https://github.example.com/api/v3/": "https://github.example.com/api/v3",
            "  https://GitHub.Example.com:8443/api/v3  ": "https://github.example.com:8443/api/v3",
            "https://api.corp.ghe.com": "https://api.corp.ghe.com",
            "https://localhost": "https://localhost",
            "http://localhost:8080": "http://localhost:8080",
            "http://127.0.0.1:9000": "http://127.0.0.1:9000",
            "http://[::1]:9000": "http://[::1]:9000",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(github_api.validate_api_base_url(raw), expected)

    def test_rejects_invalid_urls(self):
        cases = [
            "",
            "   ",
            None,
            123,
            "github.example.com/api/v3",
            "ftp://github.example.com/api/v3",
            "http://github.example.com/api/v3",
            "http://localhost.evil.com",
            "http://127.0.0.1.evil.com",
            "http://0.0.0.0:80",
            "https://",
            "https://user:pass@github.example.com/api/v3",
            "https://user@github.example.com/api/v3",
            "https://github.example.com/api/v3?x=1",
            "https://github.example.com/api/v3#frag",
            "https://github.example.com/other",
            "https://github.example.com/api/v4",
            "https://github.example.com:notaport/api/v3",
            "https://github.example.com:70000/api/v3",
            "https://github.example.com/api/v3 extra",
            "https://github.example.com/\napi",
            "https://" + "a" * 3000 + ".com",
        ]
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaises(github_api.InvalidApiUrlError):
                    github_api.validate_api_base_url(raw)

    def test_error_messages_do_not_leak_the_url(self):
        with self.assertRaises(github_api.InvalidApiUrlError) as raised:
            github_api.validate_api_base_url("https://user:s3cr3t@github.example.com/api/v3")
        self.assertNotIn("s3cr3t", str(raised.exception))

    def test_invalid_url_error_is_a_github_api_error(self):
        self.assertTrue(issubclass(github_api.InvalidApiUrlError, github_api.GitHubApiError))


class ApiHostnameTests(unittest.TestCase):
    def test_maps_base_urls_to_gh_hostnames(self):
        cases = {
            "https://api.github.com": "github.com",
            "https://github.example.com/api/v3": "github.example.com",
            "https://api.github.example.com/api/v3": "api.github.example.com",
            "https://api.corp.ghe.com": "corp.ghe.com",
            "https://github.example.com:8443/api/v3": "github.example.com:8443",
            "http://127.0.0.1:9000": "127.0.0.1:9000",
            "http://[::1]:9000": "[::1]:9000",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(github_api.api_hostname(raw), expected)

    def test_invalid_url_is_rejected(self):
        with self.assertRaises(github_api.InvalidApiUrlError):
            github_api.api_hostname("http://github.example.com")


class GhHostArgumentsTests(unittest.TestCase):
    def test_unset_or_blank_leaves_default_behavior(self):
        self.assertEqual(github_api.gh_host_arguments({}), [])
        self.assertEqual(github_api.gh_host_arguments({github_api.API_URL_ENV: "  "}), [])

    def test_configured_url_selects_hostname(self):
        env = {github_api.API_URL_ENV: "https://github.example.com/api/v3"}
        self.assertEqual(
            github_api.gh_host_arguments(env),
            ["--hostname", "github.example.com"],
        )

    def test_invalid_configured_url_raises(self):
        env = {github_api.API_URL_ENV: "http://github.example.com/api/v3"}
        with self.assertRaises(github_api.InvalidApiUrlError):
            github_api.gh_host_arguments(env)


class RunGhTests(unittest.TestCase):
    def fake_run(self):
        result = mock.Mock(returncode=0, stdout="{}", stderr="")
        return mock.patch("github_api.subprocess.run", return_value=result)

    def test_default_command_is_unchanged(self):
        with mock.patch.dict(os.environ, env_without_override(), clear=True):
            with self.fake_run() as run:
                github_api.run_gh(["repos/o/r/issues/1/comments"])
        self.assertEqual(run.call_args.args[0], ["gh", "api", "repos/o/r/issues/1/comments"])

    def test_configured_url_adds_hostname(self):
        env = env_without_override()
        env[github_api.API_URL_ENV] = "https://github.example.com/api/v3"
        with mock.patch.dict(os.environ, env, clear=True):
            with self.fake_run() as run:
                github_api.run_gh(["--method", "POST", "repos/o/r/check-runs"])
        self.assertEqual(
            run.call_args.args[0],
            ["gh", "api", "--hostname", "github.example.com", "--method", "POST", "repos/o/r/check-runs"],
        )

    def test_invalid_url_never_reaches_gh(self):
        env = env_without_override()
        env[github_api.API_URL_ENV] = "http://github.example.com/api/v3"
        with mock.patch.dict(os.environ, env, clear=True):
            with self.fake_run() as run:
                with self.assertRaises(github_api.InvalidApiUrlError):
                    github_api.run_gh(["repos/o/r/check-runs"])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
