"""Typed JSON shapes for the documented soroban-scan API.

The shapes follow ``docs/service-api.md`` (job lifecycle) and
``docs/integration/openapi.json`` (health, synchronous scan, jobs, report, and
rules). Unknown extra fields returned by newer servers are left in the mapping;
these types describe the fields the client relies on, not a closed schema.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Literal, TypedDict

Severity = str
Confidence = Literal["low", "medium", "high"]
JobStatus = Literal["queued", "running", "completed", "failed"]
ScanJobStatusValue = Literal["queued", "running", "done", "failed"]
TokenProvider = Callable[[], str]

JsonObject = Dict[str, Any]


class _ApiErrorBodyOptional(TypedDict, total=False):
    details: Any


class ApiErrorBody(_ApiErrorBodyOptional):
    """Structured error body: ``{"code", "message"}`` (plus optional details)."""

    code: str
    message: str


class _FindingOptional(TypedDict, total=False):
    title: str
    confidence: Confidence
    description: str
    evidence: str
    remediation: str
    category: str
    fingerprint: str
    references: List[str]
    location: JsonObject
    exploitability: JsonObject


class Finding(_FindingOptional):
    """One finding from a scan report."""

    rule_id: str
    severity: Severity


class Report(TypedDict):
    """The report schema ``1`` documented in ``docs/integration/report.schema.json``."""

    schema_version: str
    tool: JsonObject
    project: JsonObject
    stats: JsonObject
    effective_config: JsonObject
    findings: List[Finding]
    diagnostics: List[Any]


class ScanSubmission(TypedDict):
    """Response of ``POST /v1/scans``."""

    job_id: str
    status: JobStatus


class _JobOptional(TypedDict, total=False):
    report: Report
    error: ApiErrorBody


class Job(_JobOptional):
    """Response of ``GET /v1/jobs/{id}`` in the in-process service API."""

    job_id: str
    status: str


class CompletedJob(TypedDict):
    """A job normalized to its completed state by ``wait_for_job``."""

    job_id: str
    status: Literal["completed"]
    report: Report


class ScanJobStatus(TypedDict):
    """Response of ``POST /v1/jobs`` and ``GET /v1/jobs/{job_id}`` (OpenAPI)."""

    job_id: str
    status: ScanJobStatusValue
    created_at: str
    expires_at: str


class HealthResponse(TypedDict):
    """Response of ``GET /v1/health``; this route needs no authentication."""

    status: str
    tool: str
    version: str


class SourceFileInput(TypedDict):
    """A single bounded in-memory source file for ``POST /v1/scan``."""

    path: str
    content: str


class _ScanRequestOptional(TypedDict, total=False):
    mode: str
    enabled_rules: List[str]
    disabled_rules: List[str]
    min_severity: str
    min_confidence: str
    max_findings: int


class ScanRequest(_ScanRequestOptional):
    """Body of the synchronous ``POST /v1/scan`` endpoint."""

    files: List[SourceFileInput]


class _ScanJobRequestOptional(TypedDict, total=False):
    ttl_seconds: int


class ScanJobRequest(_ScanJobRequestOptional):
    """Body of ``POST /v1/jobs``."""

    scan: ScanRequest


class RuleDetail(TypedDict):
    """Metadata for one detector in ``/v1/rules``."""

    id: str
    title: str
    description: str
    default_severity: str
    default_confidence: str
    category: str
    remediation: str
    references: List[str]


class RuleListResponse(TypedDict):
    """Response of ``GET /v1/rules``."""

    rules: List[RuleDetail]


class _SubmitScanRequestOptional(TypedDict, total=False):
    file: str


class SubmitScanRequest(_SubmitScanRequestOptional):
    """Body of ``POST /v1/scans``."""

    source: str


class _PollOptions(TypedDict, total=False):
    interval_ms: int
    timeout_ms: int


PollOptions = _PollOptions
