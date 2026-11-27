"""Typed errors for the soroban-scan HTTP client.

Every exception raised by this package derives from :class:`SorobanScanError`,
so callers can catch the whole family with one type. Messages are deliberately
generic: tokens, submitted source, and raw HTML error pages are never echoed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .types import ApiErrorBody, Job


class SorobanScanError(Exception):
    """Base class for every error raised by this package."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class InvalidBaseUrlError(SorobanScanError):
    """The configured base URL is missing, malformed, or unsafe."""


class InvalidResponseError(SorobanScanError):
    """The server sent a body that does not match the documented schema."""


class ClientTimeoutError(SorobanScanError):
    """A single HTTP request exceeded its configured timeout."""


class TransportError(SorobanScanError):
    """The request could not be completed at the transport layer."""


class RedirectError(SorobanScanError):
    """The server tried to redirect; redirects are refused to protect the token."""


class ResponseTooLargeError(SorobanScanError):
    """The response exceeded the configured byte limit."""


class PollTimeoutError(SorobanScanError):
    """A job did not reach a terminal state within the polling budget."""


class ApiError(SorobanScanError):
    """The server answered with a non-2xx status.

    ``code`` is the stable code from the structured API error body, or
    ``http_<status>`` when no structured body was returned. ``retry_after`` is
    populated from a bounded ``Retry-After`` header on rate-limit responses.
    """

    def __init__(
        self,
        status: int,
        body: ApiErrorBody | None = None,
        *,
        retry_after: int | None = None,
    ) -> None:
        code = body["code"] if body else f"http_{status}"
        message = body["message"] if body else f"HTTP {status}"
        super().__init__(f"{code}: {message} (HTTP {status})")
        self.status = status
        self.code = code
        self.details: Any = body.get("details") if body else None
        self.retry_after = retry_after

    def __str__(self) -> str:
        return self.message


class ScanFailedError(SorobanScanError):
    """The job reached the ``failed`` state."""

    def __init__(self, job: Job) -> None:
        error = job.get("error")
        if error:
            message = (
                f"scan job {job['job_id']} failed: "
                f"{error['code']}: {error['message']}"
            )
        else:
            message = f"scan job {job['job_id']} failed"
        super().__init__(message)
        self.job = job


class JobNotFinishedError(SorobanScanError):
    """The report was requested before the job reached a terminal state."""
