#!/usr/bin/env python3
"""Small wrapper around ``gh api`` for the GitHub integration scripts.

The workflows pass a short-lived ``GITHUB_TOKEN`` through the environment. This
module never prints, stores, or forwards that token: authentication is handled
entirely by the ``gh`` CLI.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import time
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

# Bounded retries for read-only requests. Mutating requests are never retried:
# GitHub does not deduplicate comment or check-run creation, so a retry could
# post twice.
MAX_READ_ATTEMPTS = 3
RETRY_DELAY_SECONDS = 0.2
_TRANSIENT = re.compile(
    r"\bHTTP (?:429|5\d\d)\b|timed out|connection reset|temporary failure",
    re.IGNORECASE,
)


class GitHubApiError(RuntimeError):
    """Raised when ``gh api`` exits unsuccessfully."""


# Opt-in override for GitHub Enterprise Server / GHE.com. When unset, ``gh``
# talks to github.com exactly as before.
API_URL_ENV = "SOROBAN_SCAN_GITHUB_API_URL"
_MAX_API_URL_LENGTH = 2048
_ALLOWED_API_PATHS = ("", "/api/v3")
_MAX_REPO_LENGTH = 200
_REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_MAX_INSTALLATION_ID = 2**63 - 1


class InvalidApiUrlError(GitHubApiError):
    """Raised when the configured GitHub API base URL is not acceptable."""


class InvalidInstallationError(GitHubApiError):
    """Raised when a GitHub App installation cannot be used safely."""


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

def _is_read_only(arguments: Sequence[str]) -> bool:
    """True when ``gh api`` will not change server state."""

    if "--method" not in arguments:
        return True
    method = arguments[arguments.index("--method") + 1].upper()
    return method in {"GET", "HEAD"}


def run_gh(
    arguments: Sequence[str],
    payload: dict[str, Any] | None = None,
    *,
    timeout: int = 60,
    attempts: int = MAX_READ_ATTEMPTS,
    retry_delay: float = RETRY_DELAY_SECONDS,
) -> str:
    """Runs ``gh api`` with ``arguments`` and returns stdout.

    ``payload`` is sent as a JSON request body through stdin so comment bodies
    and annotation summaries never have to be escaped into command-line
    arguments.

    Read-only requests retry transient failures (HTTP 429, HTTP 5xx, timeouts,
    and connection resets) up to ``attempts`` times. Mutating requests run
    exactly once because GitHub does not deduplicate their effects.
    """

    command = ["gh", "api", *gh_host_arguments(), *arguments]
    attempts = max(1, attempts) if _is_read_only(arguments) else 1
    for attempt in range(1, attempts + 1):
        result = subprocess.run(
            command,
            input=json.dumps(payload) if payload is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
        message = result.stderr.strip() or result.stdout.strip()
        if attempt == attempts or not _TRANSIENT.search(message):
            raise GitHubApiError(
                f"gh api failed with exit code {result.returncode}: {message}"
            )
        time.sleep(retry_delay)
    raise AssertionError("unreachable")


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


def validate_repo(repo: object) -> str:
    """Validates an ``OWNER/REPO`` name before it is used in an endpoint.

    Bounds the length and character set so an untrusted value cannot smuggle a
    query string, extra path segments, or control characters into ``gh api``.
    Error messages never echo the input.
    """

    if not isinstance(repo, str):
        raise GitHubApiError("repository must be a string")
    value = repo.strip()
    if (
        not value
        or len(value) > _MAX_REPO_LENGTH
        or _REPO_PATTERN.fullmatch(value) is None
    ):
        raise GitHubApiError("repository must be OWNER/REPO")
    return value


def installation_id(value: object) -> int:
    """Extracts a bounded installation id from an API response.

    Only the numeric identifier is returned. Credentials, tokens, and any other
    fields in the response are deliberately discarded so callers cannot persist
    them by accident.
    """

    if not isinstance(value, dict):
        raise InvalidInstallationError(
            "unexpected response when reading an installation"
        )
    identifier = value.get("id")
    if isinstance(identifier, bool) or not isinstance(identifier, int):
        raise InvalidInstallationError("installation id must be a positive integer")
    if not 0 < identifier <= _MAX_INSTALLATION_ID:
        raise InvalidInstallationError("installation id is out of range")
    return identifier


def get_installation(
    repo: str,
    *,
    runner: Callable[..., str] = run_gh,
) -> dict[str, Any]:
    """Returns the GitHub App installation that covers ``repo``.

    Workflows that use ``GITHUB_TOKEN`` do not need this lookup; it exists for
    callers that install a GitHub App. Prefer :func:`get_installation_id`, which
    returns only the identifier and discards every other response field.
    """

    endpoint = f"repos/{validate_repo(repo)}/installation"
    response = parse_json(runner([endpoint]))
    if not isinstance(response, dict):
        raise GitHubApiError("unexpected response when reading an installation")
    return response


def get_installation_id(
    repo: str,
    *,
    runner: Callable[..., str] = run_gh,
) -> int:
    """Returns the validated installation id covering ``repo``.

    This is the only value callers need to persist. Installation access tokens
    and user tokens must be minted just in time, kept in memory or the ``gh``
    environment, and never written to configuration or reports. The lookup is a
    read-only request and is opt-in: default workflows keep using
    ``GITHUB_TOKEN``.
    """

    return installation_id(get_installation(repo, runner=runner))


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
