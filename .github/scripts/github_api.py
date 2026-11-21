#!/usr/bin/env python3
"""Small wrapper around ``gh api`` for the GitHub integration scripts.

The workflows pass a short-lived ``GITHUB_TOKEN`` through the environment. This
module never prints, stores, or forwards that token: authentication is handled
entirely by the ``gh`` CLI.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from typing import Any, Callable, Sequence

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

    command = ["gh", "api", *arguments]
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


def get_installation(
    repo: str,
    *,
    runner: Callable[..., str] = run_gh,
) -> dict[str, Any]:
    """Returns the GitHub App installation that covers ``repo``.

    Workflows that use ``GITHUB_TOKEN`` do not need this lookup; it exists for
    callers that install a GitHub App and need the installation id.
    """

    endpoint = f"repos/{repo}/installation"
    response = parse_json(runner([endpoint]))
    if not isinstance(response, dict):
        raise GitHubApiError("unexpected response when reading an installation")
    return response


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
