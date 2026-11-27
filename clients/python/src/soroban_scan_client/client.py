"""Dependency-free, typed Python client for the soroban-scan HTTP API.

The client covers both documented surfaces: the in-process service API in
``docs/service-api.md`` (``POST /v1/scans`` and ``GET /v1/jobs/{id}``) and the
OpenAPI 3.1 contract in ``docs/integration/openapi.json`` (health, synchronous
scan, job submission, report retrieval, and the rule catalog).

Safety rules built into every request:

* Bearer authentication is explicit and validated; tokens are never echoed in
  errors and are not sent to a redirected host (redirects are refused).
* HTTPS is required except for loopback hosts, which keeps mock servers usable.
* Requests, responses, polling, and retry counts are all bounded.
* Only idempotent ``GET`` calls are retried. Submissions are never retried
  blindly, because a retried ``POST`` could queue duplicate work.
"""

from __future__ import annotations

import json
import re
import time
from http.client import HTTPException
from typing import Any, Dict, List, Mapping, Tuple, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from .errors import (
    ApiError,
    ClientTimeoutError,
    InvalidBaseUrlError,
    InvalidResponseError,
    JobNotFinishedError,
    PollTimeoutError,
    RedirectError,
    ResponseTooLargeError,
    ScanFailedError,
    SorobanScanError,
    TransportError,
)
from .types import (
    ApiErrorBody,
    CompletedJob,
    HealthResponse,
    Job,
    Report,
    RuleDetail,
    RuleListResponse,
    ScanJobRequest,
    ScanJobStatus,
    ScanJobStatusValue,
    ScanRequest,
    ScanSubmission,
    SubmitScanRequest,
    TokenProvider,
)

MAX_URL_LENGTH = 2048
MAX_TOKEN_LENGTH = 4096
DEFAULT_TIMEOUT = 30.0
MAX_TIMEOUT = 300.0
DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024
MAX_BYTES_LIMIT = 100 * 1024 * 1024
DEFAULT_MAX_RETRIES = 2
MAX_RETRIES = 5
DEFAULT_RETRY_BACKOFF = 0.05
MAX_RETRY_BACKOFF = 5.0
DEFAULT_MAX_RETRY_DELAY = 2.0
MAX_RETRY_DELAY = 30.0
DEFAULT_POLL_INTERVAL_MS = 1000
MAX_POLL_INTERVAL_MS = 60_000
DEFAULT_POLL_TIMEOUT_MS = 600_000
MAX_POLL_TIMEOUT_MS = 3_600_000
MAX_FINDINGS = 10_000
MAX_RULES = 1024
RETRYABLE_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
JOB_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
FILE_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,126}\.rs$")
RULE_ID_RE = re.compile(r"^SS-[0-9]{3}$")
JOB_STATES = frozenset({"queued", "running", "completed", "failed", "done"})
SCAN_JOB_STATES = frozenset({"queued", "running", "done", "failed"})
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})
CONFIDENCES = frozenset({"low", "medium", "high"})
MODES = frozenset({"soroban", "generic", "auto"})
REPORT_REQUIRED_OBJECTS = ("tool", "project", "stats", "effective_config")
RULE_REQUIRED_STRINGS = (
    "title",
    "description",
    "default_severity",
    "default_confidence",
    "category",
    "remediation",
)


class _NoRedirect(HTTPRedirectHandler):
    """Refuse redirects so a bearer token is never forwarded to another host."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        raise RedirectError("redirects are refused by this client")


def _has_unsafe_chars(value: str) -> bool:
    return any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value)


def validate_base_url(value: object) -> str:
    """Validate and normalize an API base URL.

    HTTPS is required; plain HTTP is allowed only for loopback hosts so local
    mock servers keep working. Credentials, query strings, fragments, control
    characters, and over-long URLs are rejected. Error messages never include
    the URL, so a secret pasted into it cannot leak into logs.
    """

    if not isinstance(value, str):
        raise InvalidBaseUrlError("base URL must be a string")
    raw = value.strip()
    if not raw:
        raise InvalidBaseUrlError("base URL must not be empty")
    if len(raw) > MAX_URL_LENGTH:
        raise InvalidBaseUrlError("base URL is too long")
    if _has_unsafe_chars(raw):
        raise InvalidBaseUrlError("base URL must not contain whitespace or control characters")
    if "?" in raw or "#" in raw:
        raise InvalidBaseUrlError("base URL must not contain a query string or fragment")

    try:
        parts = urlsplit(raw)
    except ValueError:
        raise InvalidBaseUrlError("base URL is not a valid absolute URL") from None
    scheme = parts.scheme.lower()
    if scheme not in ("https", "http"):
        raise InvalidBaseUrlError("base URL must use https")
    if scheme == "http" and (parts.hostname or "") not in LOOPBACK_HOSTS:
        raise InvalidBaseUrlError("base URL must use https (http is allowed only for loopback hosts)")
    if parts.username or parts.password:
        raise InvalidBaseUrlError("base URL must not embed credentials")
    if not parts.netloc or not parts.hostname:
        raise InvalidBaseUrlError("base URL is not a valid absolute URL")

    path = parts.path.rstrip("/")
    return f"{scheme}://{parts.netloc}{path}"


def validate_token(value: object) -> str:
    """Validate a bearer token without ever including it in an error."""

    if not isinstance(value, str):
        raise SorobanScanError("token must be a string or a callable returning one")
    if not value or len(value) > MAX_TOKEN_LENGTH or _has_unsafe_chars(value):
        raise SorobanScanError(
            "token must be non-empty and free of whitespace or control characters "
            "(max 4096 characters)"
        )
    return value


def _bounded_number(
    name: str,
    value: object,
    default: float,
    minimum: float,
    maximum: float,
    *,
    integer: bool = False,
) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SorobanScanError(f"{name} must be a number between {minimum} and {maximum}")
    if integer and not isinstance(value, int):
        raise SorobanScanError(f"{name} must be an integer between {minimum} and {maximum}")
    if not minimum <= value <= maximum:
        raise SorobanScanError(f"{name} must be between {minimum} and {maximum}")
    return value


def _bounded_integer(name: str, value: object, default: int, minimum: int, maximum: int) -> int:
    return int(_bounded_number(name, value, default, minimum, maximum, integer=True))


def _require_mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SorobanScanError(f"{label} must be an object")
    return value


def _require_string(value: object, label: str, max_length: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise SorobanScanError(f"{label} must be a non-empty string of at most {max_length} characters")
    return value


def _validate_job_id(value: object) -> str:
    if not isinstance(value, str) or not JOB_ID_RE.fullmatch(value):
        raise SorobanScanError(
            "job id must be 1-128 characters of A-Z, a-z, 0-9, '.', '_' or '-'"
        )
    return value


def _validate_rule_id(value: object) -> str:
    if not isinstance(value, str) or not RULE_ID_RE.fullmatch(value):
        raise SorobanScanError("rule id must look like SS-001")
    return value


def _truncate(value: str, limit: int) -> str:
    return value[:limit]


def _redact(value: str, secrets: Tuple[str, ...]) -> str:
    result = value
    for secret in secrets:
        if secret:
            result = result.replace(secret, "[redacted]")
    return result


def _parse_error_body(value: object, secrets: Tuple[str, ...]) -> ApiErrorBody | None:
    if not isinstance(value, dict):
        return None
    candidate: object = value
    nested = value.get("error")
    if isinstance(nested, dict):
        candidate = nested
    if not isinstance(candidate, dict):
        return None
    code = candidate.get("code")
    message = candidate.get("message")
    if not isinstance(code, str) or not isinstance(message, str):
        return None
    return cast(
        ApiErrorBody,
        {
            "code": _truncate(_redact(code, secrets), 100),
            "message": _truncate(_redact(message, secrets), 500),
            "details": candidate.get("details"),
        },
    )


def _parse_error_text(text: str, secrets: Tuple[str, ...]) -> ApiErrorBody | None:
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except ValueError:
        return None
    return _parse_error_body(parsed, secrets)


def _retry_after(header: object) -> int | None:
    if not isinstance(header, str) or not header.strip().isdigit():
        return None
    return min(int(header.strip()), int(MAX_RETRY_DELAY))


def _validate_report(value: object) -> Report:
    if not isinstance(value, dict):
        raise InvalidResponseError("report must be a JSON object")
    if value.get("schema_version") != "1":
        raise InvalidResponseError("unsupported report schema_version")
    for key in REPORT_REQUIRED_OBJECTS:
        if not isinstance(value.get(key), dict):
            raise InvalidResponseError(f'report is missing the "{key}" object')
    findings = value.get("findings")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        raise InvalidResponseError("report has an invalid findings array")
    if "diagnostics" not in value or not isinstance(value.get("diagnostics"), list):
        raise InvalidResponseError('report is missing the "diagnostics" array')
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or not isinstance(finding.get("rule_id"), str)
            or not isinstance(finding.get("severity"), str)
        ):
            raise InvalidResponseError("report contains a malformed finding")
    return cast(Report, value)


def _validate_rule(value: object) -> RuleDetail:
    if not isinstance(value, dict):
        raise InvalidResponseError("rule must be a JSON object")
    if not isinstance(value.get("id"), str) or not RULE_ID_RE.fullmatch(value["id"]):
        raise InvalidResponseError("rule has an invalid id")
    for key in RULE_REQUIRED_STRINGS:
        if not isinstance(value.get(key), str):
            raise InvalidResponseError(f'rule is missing the "{key}" field')
    if not isinstance(value.get("references"), list):
        raise InvalidResponseError('rule is missing the "references" array')
    return cast(RuleDetail, value)


def _validate_source_file(value: object) -> None:
    item = _require_mapping(value, "source file")
    path = item.get("path")
    content = item.get("content")
    if not isinstance(path, str) or not path or len(path) > 256:
        raise SorobanScanError("source path must be a string of at most 256 characters")
    if path.startswith("/") or "\\" in path or ".." in path.split("/"):
        raise SorobanScanError("source path must be root-relative and must not contain '..'")
    if not isinstance(content, str) or len(content) > 262144:
        raise SorobanScanError("source content must be a string of at most 262144 characters")


def _validate_scan_request(value: object) -> ScanRequest:
    request = _require_mapping(value, "scan request")
    files = request.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 64:
        raise SorobanScanError("scan request must contain 1-64 files")
    for item in files:
        _validate_source_file(item)
    for key, allowed in (
        ("mode", MODES),
        ("min_severity", SEVERITIES),
        ("min_confidence", CONFIDENCES),
    ):
        if key in request and request[key] not in allowed:
            raise SorobanScanError(f"{key} has an unsupported value")
    for key in ("enabled_rules", "disabled_rules"):
        if key in request:
            values = request[key]
            if not isinstance(values, list) or len(values) > 64:
                raise SorobanScanError(f"{key} must be an array of at most 64 rule ids")
            for rule_id in values:
                _validate_rule_id(rule_id)
    if "max_findings" in request:
        _bounded_integer("max_findings", request["max_findings"], 100, 1, 10000)
    return cast(ScanRequest, dict(request))


def _validate_scan_job_request(value: object) -> ScanJobRequest:
    request = _require_mapping(value, "job request")
    if "scan" not in request:
        raise SorobanScanError("job request must contain a scan object")
    _validate_scan_request(request["scan"])
    if "ttl_seconds" in request:
        _bounded_integer("ttl_seconds", request["ttl_seconds"], 3600, 60, 86400)
    return cast(ScanJobRequest, dict(request))


class SorobanScanClient:
    """Typed client for the documented opt-in scan API.

    ``token`` may be a literal string or a zero-argument callable. A callable is
    invoked before every request, which supports rotating credentials. Only
    idempotent ``GET`` requests are retried; use ``max_retries=0`` to disable
    retries entirely.
    """

    def __init__(
        self,
        base_url: str,
        token: str | TokenProvider,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff: float = DEFAULT_RETRY_BACKOFF,
        max_retry_delay: float = DEFAULT_MAX_RETRY_DELAY,
    ) -> None:
        self._base_url = validate_base_url(base_url)
        if isinstance(token, str):
            validate_token(token)
            self._token_source: str | TokenProvider = token
        elif callable(token):
            self._token_source = token
        else:
            raise SorobanScanError("token must be a string or a callable returning one")

        self._timeout = float(
            _bounded_number("timeout", timeout, DEFAULT_TIMEOUT, 0.001, MAX_TIMEOUT)
        )
        self._max_request_bytes = _bounded_integer(
            "max_request_bytes", max_request_bytes, DEFAULT_MAX_REQUEST_BYTES, 1, MAX_BYTES_LIMIT
        )
        self._max_response_bytes = _bounded_integer(
            "max_response_bytes", max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES, 1, MAX_BYTES_LIMIT
        )
        self._max_retries = _bounded_integer(
            "max_retries", max_retries, DEFAULT_MAX_RETRIES, 0, MAX_RETRIES
        )
        self._retry_backoff = float(
            _bounded_number(
                "retry_backoff", retry_backoff, DEFAULT_RETRY_BACKOFF, 0.0, MAX_RETRY_BACKOFF
            )
        )
        self._max_retry_delay = float(
            _bounded_number(
                "max_retry_delay", max_retry_delay, DEFAULT_MAX_RETRY_DELAY, 0.0, MAX_RETRY_DELAY
            )
        )
        self._opener = build_opener(_NoRedirect)
        self._last_token: str | None = None

    # -- Public helpers ----------------------------------------------------

    def health(self) -> HealthResponse:
        """``GET /v1/health``. This route is documented as unauthenticated."""

        _, data = self._request("GET", "/v1/health", auth=False, idempotent=True)
        if not isinstance(data, dict):
            raise InvalidResponseError("health response must be a JSON object")
        for key in ("status", "tool", "version"):
            if not isinstance(data.get(key), str):
                raise InvalidResponseError(f'health response is missing "{key}"')
        return cast(HealthResponse, data)

    def submit_scan(self, request: SubmitScanRequest | Mapping[str, Any]) -> ScanSubmission:
        """``POST /v1/scans``: queue a single source file. Never retried."""

        payload = self._validate_submit_request(request)
        _, data = self._request("POST", "/v1/scans", body=payload)
        if not isinstance(data, dict):
            raise InvalidResponseError("submission response must be a JSON object")
        job_id = data.get("job_id")
        if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
            raise InvalidResponseError("submission response has an invalid job id")
        status = data.get("status", "queued")
        if status not in JOB_STATES:
            raise InvalidResponseError("submission response has an unknown status")
        return cast(ScanSubmission, {"job_id": job_id, "status": status})

    def scan(self, request: ScanRequest | Mapping[str, Any]) -> Report:
        """``POST /v1/scan``: synchronous scan. Never retried."""

        payload = _validate_scan_request(request)
        _, data = self._request("POST", "/v1/scan", body=payload)
        return _validate_report(data)

    def submit_job(self, request: ScanJobRequest | Mapping[str, Any]) -> ScanJobStatus:
        """``POST /v1/jobs``: queue a bounded job. Never retried."""

        payload = _validate_scan_job_request(request)
        _, data = self._request("POST", "/v1/jobs", body=payload)
        return self._parse_job_status(data, None)

    def get_job(self, job_id: str) -> Job:
        """``GET /v1/jobs/{id}``: current state of a service-API job."""

        expected = _validate_job_id(job_id)
        _, data = self._request("GET", f"/v1/jobs/{expected}", idempotent=True)
        if not isinstance(data, dict):
            raise InvalidResponseError("job response must be a JSON object")
        if data.get("job_id") != expected:
            raise InvalidResponseError("job response id does not match the request")
        status = data.get("status")
        if not isinstance(status, str) or status not in JOB_STATES:
            raise InvalidResponseError("job response has an unknown status")
        result: Dict[str, Any] = {"job_id": expected, "status": status}
        if "report" in data and data["report"] is not None:
            result["report"] = _validate_report(data["report"])
        secrets: Tuple[str, ...] = (self._last_token,) if self._last_token else ()
        raw_error = data.get("error")
        if status == "failed":
            error = _parse_error_body(raw_error, secrets)
            result["error"] = error or {"code": "scan_failed", "message": "scan failed"}
        elif raw_error is not None:
            error = _parse_error_body(raw_error, secrets)
            if error:
                result["error"] = error
        return cast(Job, result)

    def get_job_status(self, job_id: str) -> ScanJobStatus:
        """``GET /v1/jobs/{job_id}`` in the OpenAPI shape (with timestamps)."""

        expected = _validate_job_id(job_id)
        _, data = self._request("GET", f"/v1/jobs/{expected}", idempotent=True)
        return self._parse_job_status(data, expected)

    def wait_for_job(
        self,
        job_id: str,
        *,
        interval_ms: int = DEFAULT_POLL_INTERVAL_MS,
        timeout_ms: int = DEFAULT_POLL_TIMEOUT_MS,
    ) -> CompletedJob:
        """Poll a job until it completes, with a bounded growing delay."""

        expected = _validate_job_id(job_id)
        interval = _bounded_integer(
            "interval_ms", interval_ms, DEFAULT_POLL_INTERVAL_MS, 1, MAX_POLL_INTERVAL_MS
        )
        timeout = _bounded_integer(
            "timeout_ms", timeout_ms, DEFAULT_POLL_TIMEOUT_MS, 1, MAX_POLL_TIMEOUT_MS
        )
        delay = interval / 1000.0
        deadline = time.monotonic() + timeout / 1000.0
        max_delay = MAX_POLL_INTERVAL_MS / 1000.0

        while True:
            job = self.get_job(expected)
            status = job["status"]
            if status in ("completed", "done"):
                report = job.get("report")
                if report is None:
                    # The OpenAPI contract serves reports from a separate route.
                    report = self.fetch_report(expected)
                return cast(CompletedJob, {"job_id": expected, "status": "completed", "report": report})
            if status == "failed":
                raise ScanFailedError(job)

            remaining = deadline - time.monotonic()
            if delay >= remaining:
                raise PollTimeoutError(f"job {expected} did not finish within {timeout} ms")
            time.sleep(min(delay, remaining))
            delay = min(delay * 1.5, max_delay)

    def get_report(self, job_id: str) -> Report:
        """Return a finished job's report.

        Uses the inline report from the service API when present, otherwise the
        dedicated ``GET /v1/jobs/{job_id}/report`` route from the OpenAPI
        contract. Unfinished jobs raise :class:`JobNotFinishedError`.
        """

        expected = _validate_job_id(job_id)
        job = self.get_job(expected)
        if job["status"] == "failed":
            raise ScanFailedError(job)
        report = job.get("report")
        if report is not None:
            return report
        if job["status"] in ("completed", "done"):
            return self.fetch_report(expected)
        raise JobNotFinishedError(
            f"job {expected} is not finished (status: {job['status']})"
        )

    def fetch_report(self, job_id: str) -> Report:
        """``GET /v1/jobs/{job_id}/report``: fetch a completed job's report."""

        expected = _validate_job_id(job_id)
        _, data = self._request(
            "GET", f"/v1/jobs/{expected}/report", idempotent=True
        )
        return _validate_report(data)

    def list_rules(self) -> List[RuleDetail]:
        """``GET /v1/rules``: the registered rule catalog."""

        _, data = self._request("GET", "/v1/rules", idempotent=True)
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise InvalidResponseError('rules response must contain a "rules" array')
        rules = data["rules"]
        if len(rules) > MAX_RULES:
            raise InvalidResponseError("rules response contains too many rules")
        return [_validate_rule(rule) for rule in rules]

    def get_rule(self, rule_id: str) -> RuleDetail:
        """``GET /v1/rules/{rule_id}``: metadata for one detector."""

        expected = _validate_rule_id(rule_id)
        _, data = self._request("GET", f"/v1/rules/{expected}", idempotent=True)
        return _validate_rule(data)

    # -- Request plumbing --------------------------------------------------

    def _validate_submit_request(self, value: object) -> SubmitScanRequest:
        request = _require_mapping(value, "scan request")
        source = _require_string(request.get("source"), "source", 262144)
        result: Dict[str, Any] = {"source": source}
        if "file" in request:
            file = request["file"]
            if (
                not isinstance(file, str)
                or ".." in file
                or not FILE_NAME_RE.fullmatch(file)
            ):
                raise SorobanScanError(
                    "file must be a plain .rs file name such as lib.rs (no directories)"
                )
            result["file"] = file
        return cast(SubmitScanRequest, result)

    def _resolve_token(self) -> str:
        source = self._token_source
        token = source() if callable(source) else source
        return validate_token(token)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        auth: bool = True,
        idempotent: bool = False,
    ) -> Tuple[int, object]:
        attempts = self._max_retries + 1 if idempotent else 1
        for attempt in range(attempts):
            try:
                return self._request_once(method, path, body=body, auth=auth)
            except (ClientTimeoutError, TransportError, ApiError) as exc:
                if attempt + 1 == attempts:
                    raise
                delay = self._retry_delay(exc, attempt)
                if delay is None:
                    raise
                time.sleep(delay)

        raise AssertionError("unreachable")  # pragma: no cover

    def _retry_delay(self, exc: SorobanScanError, attempt: int) -> float | None:
        if isinstance(exc, ApiError):
            if exc.status not in RETRYABLE_STATUSES:
                return None
            if exc.retry_after is not None:
                return float(min(exc.retry_after, self._max_retry_delay))
        return min(self._retry_backoff * (2**attempt), self._max_retry_delay)

    def _request_once(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None,
        auth: bool,
    ) -> Tuple[int, object]:
        token = self._resolve_token() if auth else None
        self._last_token = token
        secrets: Tuple[str, ...] = (token,) if token else ()
        payload: bytes | None = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            if len(payload) > self._max_request_bytes:
                raise SorobanScanError("request body exceeds the configured size limit")

        headers = {"Accept": "application/json", "User-Agent": "soroban-scan-python/0.1"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if payload is not None:
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self._base_url}{path}", data=payload, headers=headers, method=method
        )

        try:
            response = self._opener.open(request, timeout=self._timeout)
        except HTTPError as exc:
            text = self._read_body(exc)
            parsed = _parse_error_text(text, secrets)
            raise ApiError(
                exc.code, parsed, retry_after=_retry_after(exc.headers.get("Retry-After"))
            ) from None
        except URLError as exc:
            if isinstance(exc.reason, TimeoutError):
                raise ClientTimeoutError(
                    f"request timed out after {self._timeout:g} seconds"
                ) from None
            raise TransportError("request failed") from None
        except TimeoutError:
            raise ClientTimeoutError(
                f"request timed out after {self._timeout:g} seconds"
            ) from None
        except (HTTPException, OSError):
            raise TransportError("request failed") from None

        with response:
            text = self._read_body(response)
        if not text:
            raise InvalidResponseError("response body is empty")
        try:
            data = json.loads(text)
        except (ValueError, UnicodeDecodeError):
            raise InvalidResponseError("response body is not valid JSON") from None
        return getattr(response, "status", 200), data

    def _read_body(self, response: Any) -> str:
        limit = self._max_response_bytes
        declared = response.headers.get("Content-Length")
        if declared and declared.strip().isdigit() and int(declared.strip()) > limit:
            raise ResponseTooLargeError("response body exceeds the configured size limit")

        chunks: List[bytes] = []
        total = 0
        while True:
            chunk = response.read(min(65536, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ResponseTooLargeError("response body exceeds the configured size limit")
            chunks.append(chunk)
        try:
            return b"".join(chunks).decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidResponseError("response body is not valid UTF-8") from None

    def _parse_job_status(self, value: object, expected: str | None) -> ScanJobStatus:
        if not isinstance(value, dict):
            raise InvalidResponseError("job status response must be a JSON object")
        job_id = value.get("job_id")
        if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
            raise InvalidResponseError("job status response has an invalid job id")
        if expected is not None and job_id != expected:
            raise InvalidResponseError("job response id does not match the request")
        status = value.get("status")
        if not isinstance(status, str) or status not in SCAN_JOB_STATES:
            raise InvalidResponseError("job status response has an unknown status")
        for key in ("created_at", "expires_at"):
            if not isinstance(value.get(key), str):
                raise InvalidResponseError(f'job status response is missing "{key}"')
        result = {
            "job_id": job_id,
            "status": cast(ScanJobStatusValue, status),
            "created_at": value["created_at"],
            "expires_at": value["expires_at"],
        }
        return cast(ScanJobStatus, result)


__all__ = [
    "ApiError",
    "ClientTimeoutError",
    "InvalidBaseUrlError",
    "InvalidResponseError",
    "JobNotFinishedError",
    "PollTimeoutError",
    "RedirectError",
    "ResponseTooLargeError",
    "ScanFailedError",
    "SorobanScanClient",
    "SorobanScanError",
    "TransportError",
    "validate_base_url",
    "validate_token",
]
