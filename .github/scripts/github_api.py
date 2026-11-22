#!/usr/bin/env python3
"""Small wrapper around ``gh api`` for the GitHub integration scripts.

The workflows pass a short-lived ``GITHUB_TOKEN`` through the environment. This
module never prints, stores, or forwards that token: authentication is handled
entirely by the ``gh`` CLI.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Callable, Sequence


class GitHubApiError(RuntimeError):
    """Raised when ``gh api`` exits unsuccessfully."""

# Opt-in override for GitHub Enterprise Server / GHE.com. When unset, ``gh``
# talks to github.com exactly as before.
API_URL_ENV = "SOROBAN_SCAN_GITHUB_API_URL"
_MAX_API_URL_LENGTH = 2048
_ALLOWED_API_PATHS = ("", "/api/v3")


class InvalidApiUrlError(GitHubApiError):
    """Raised when the configured GitHub API base URL is not acceptable."""


def _is_loopback_host(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_api_base_url(value: object) -> str:
    """Validates a GitHub API base URL and returns its normalized form.

    Accepted: ``https`` URLs whose path is empty or ``/api/v3``, plus plain
    ``http`` for loopback hosts only (local mock servers). Rejected: other
    schemes, embedded credentials, query strings, fragments, other paths,
    whitespace/control characters and URLs longer than 2048 characters.

    Error messages deliberately never include the URL so that a secret
    embedded by mistake cannot leak into CI logs.
    """

    if not isinstance(value, str):
        raise InvalidApiUrlError("GitHub API URL must be a string")
    url = value.strip()
    if not url:
        raise InvalidApiUrlError("GitHub API URL must not be empty")
    if len(url) > _MAX_API_URL_LENGTH:
        raise InvalidApiUrlError("GitHub API URL is too long")
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in url):
        raise InvalidApiUrlError("GitHub API URL must not contain whitespace or control characters")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as error:
        raise InvalidApiUrlError(f"GitHub API URL is malformed: {error}") from None
    hostname = parts.hostname or ""
    if parts.scheme not in ("https", "http"):
        raise InvalidApiUrlError("GitHub API URL must use https")
    if not hostname:
        raise InvalidApiUrlError("GitHub API URL must include a host")
    if parts.scheme == "http" and not _is_loopback_host(hostname):
        raise InvalidApiUrlError("GitHub API URL must use https (http is allowed only for loopback hosts)")
    if parts.username is not None or parts.password is not None:
        raise InvalidApiUrlError("GitHub API URL must not embed credentials")
    if parts.query or parts.fragment:
        raise InvalidApiUrlError("GitHub API URL must not contain a query string or fragment")
    path = parts.path.rstrip("/")
    if path not in _ALLOWED_API_PATHS:
        raise InvalidApiUrlError("GitHub API URL path must be empty or /api/v3")
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    if port is not None:
        netloc = f"{netloc}:{port}"
    return f"{parts.scheme}://{netloc}{path}"


def api_hostname(base_url: str) -> str:
    """Returns the ``gh api --hostname`` value for a validated base URL.

    ``https://api.github.com`` maps to ``github.com`` and a GHE.com style
    ``https://api.<tenant>.ghe.com`` maps to ``<tenant>.ghe.com``. A GitHub
    Enterprise Server URL (``https://host/api/v3``) maps to ``host``.
    """

    parts = urlsplit(validate_api_base_url(base_url))
    hostname = parts.hostname or ""
    if parts.path == "" and hostname.startswith("api.") and len(hostname) > len("api."):
        hostname = hostname[len("api."):]
    if ":" in hostname:
        hostname = f"[{hostname}]"
    return f"{hostname}:{parts.port}" if parts.port else hostname


def gh_host_arguments(environ: Mapping[str, str] | None = None) -> list[str]:
    """Returns extra ``gh api`` arguments selecting the configured API host.

    Empty when ``SOROBAN_SCAN_GITHUB_API_URL`` is unset or blank. Raises
    :class:`InvalidApiUrlError` when it is set to an unacceptable value.
    """

    source = os.environ if environ is None else environ
    raw = source.get(API_URL_ENV, "")
    if not raw.strip():
        return []
    return ["--hostname", api_hostname(raw)]


def run_gh(
    arguments: Sequence[str],
    payload: dict[str, Any] | None = None,
    *,
    timeout: int = 60,
) -> str:
    """Runs ``gh api`` with ``arguments`` and returns stdout.

    ``payload`` is sent as a JSON request body through stdin so comment bodies
    and annotation summaries never have to be escaped into command-line
    arguments.
    """

    command = ["gh", "api", *gh_host_arguments(), *arguments]
    result = subprocess.run(
        command,
        input=json.dumps(payload) if payload is not None else None,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip()
        raise GitHubApiError(f"gh api failed with exit code {result.returncode}: {message}")
    return result.stdout


def parse_json(text: str) -> Any:
    """Parses a ``gh api`` response, treating an empty response as ``None``."""

    text = text.strip()
    if not text:
        return None
    return json.loads(text)


def list_comments(repo: str, number: int, *, runner: Callable[..., str] = run_gh) -> list[dict[str, Any]]:
    """Returns every issue/PR comment, following GitHub pagination."""

    endpoint = f"repos/{repo}/issues/{number}/comments?per_page=100"
    pages = parse_json(runner(["--paginate", "--slurp", endpoint]))
    if pages is None:
        return []
    # ``--slurp`` wraps each page in an outer array. Older gh versions emit a
    # flat array when there is only one page, so tolerate both shapes.
    if pages and isinstance(pages[0], dict):
        return list(pages)
    comments: list[dict[str, Any]] = []
    for page in pages:
        comments.extend(page)
    return comments


def create_comment(
    repo: str,
    number: int,
    body: str,
    *,
    runner: Callable[..., str] = run_gh,
) -> dict[str, Any]:
    """Creates a comment and returns the API response."""

    endpoint = f"repos/{repo}/issues/{number}/comments"
    response = parse_json(
        runner(["--method", "POST", "--input", "-", endpoint], {"body": body})
    )
    if not isinstance(response, dict):
        raise GitHubApiError("unexpected response when creating a comment")
    return response


def update_comment(
    repo: str,
    comment_id: int,
    body: str,
    *,
    runner: Callable[..., str] = run_gh,
) -> dict[str, Any]:
    """Updates an existing comment and returns the API response."""

    endpoint = f"repos/{repo}/issues/comments/{comment_id}"
    response = parse_json(
        runner(["--method", "PATCH", "--input", "-", endpoint], {"body": body})
    )
    if not isinstance(response, dict):
        raise GitHubApiError("unexpected response when updating a comment")
    return response


def delete_comment(
    repo: str,
    comment_id: int,
    *,
    runner: Callable[..., str] = run_gh,
) -> None:
    """Deletes a comment. GitHub returns ``204 No Content`` on success."""

    endpoint = f"repos/{repo}/issues/comments/{comment_id}"
    runner(["--method", "DELETE", endpoint])


def create_check_run(
    repo: str,
    payload: dict[str, Any],
    *,
    runner: Callable[..., str] = run_gh,
) -> dict[str, Any]:
    """Creates a check run and returns the API response."""

    endpoint = f"repos/{repo}/check-runs"
    response = parse_json(
        runner(["--method", "POST", "--input", "-", endpoint], payload)
    )
    if not isinstance(response, dict):
        raise GitHubApiError("unexpected response when creating a check run")
    return response
