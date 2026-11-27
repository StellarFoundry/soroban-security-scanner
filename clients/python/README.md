# soroban-scan-client (Python)

A typed, dependency-free Python client (3.10+) for the opt-in soroban-scan HTTP
API. It covers both documented surfaces: the in-process service API in
[service-api.md](../../docs/service-api.md) and the HTTP contract in
[openapi.json](../../docs/integration/openapi.json). The repository itself ships
no HTTP listener; this client talks to a deployment that exposes that API.

The package is opt-in and never imported by the scanner CLI or the default
build. It uses only the standard library.

```python
import os

from soroban_scan_client import SorobanScanClient

client = SorobanScanClient(
    "https://scan.example.com",
    token=os.environ["SCAN_TOKEN"],  # or a callable returning a fresh token
)

# Service API: submit, poll, fetch the inline report.
submission = client.submit_scan({"source": contract_source, "file": "lib.rs"})
completed = client.wait_for_job(submission["job_id"], interval_ms=1000, timeout_ms=120_000)
for finding in completed["report"]["findings"]:
    print(finding["rule_id"], finding["severity"])

# OpenAPI contract: synchronous scan, dedicated report route, rule catalog.
report = client.scan({"files": [{"path": "src/lib.rs", "content": contract_source}]})
health = client.health()
rules = client.list_rules()
```

## Endpoints covered

| Method and path | Client method |
| --------------- | ------------- |
| `POST /v1/scans` | `submit_scan` |
| `GET /v1/jobs/{id}` | `get_job`, `get_job_status` |
| (polling `GET /v1/jobs/{id}`) | `wait_for_job` |
| `GET /v1/jobs/{job_id}/report` | `fetch_report`, `get_report` fallback |
| `GET /v1/health` | `health` |
| `POST /v1/scan` | `scan` |
| `POST /v1/jobs` | `submit_job` |
| `GET /v1/rules` | `list_rules` |
| `GET /v1/rules/{rule_id}` | `get_rule` |

Job states from both documents are accepted (`queued`, `running`, `completed`
or `done`, and `failed`). `wait_for_job` normalizes a completed job to
`status="completed"` and fetches the report from the dedicated route when the
job response does not embed one. Reports are checked against the stable
[schema version 1](../../docs/integration/report.schema.json) shape.

## Typed errors

All exceptions derive from `SorobanScanError`:

| Error | Meaning |
| ----- | ------- |
| `InvalidBaseUrlError` | Unsafe or malformed base URL. |
| `ApiError` | Non-2xx response; carries `status`, `code`, `details`, `retry_after`. |
| `ScanFailedError` | Job reached `failed`; carries the job object. |
| `PollTimeoutError` | Polling budget exhausted. |
| `JobNotFinishedError` | Report requested before the job finished. |
| `ClientTimeoutError` | A single request timed out. |
| `TransportError` | Connection failure. |
| `RedirectError` | Redirect refused so the token cannot be forwarded. |
| `ResponseTooLargeError` | Response exceeded the configured byte limit. |
| `InvalidResponseError` | Response did not match the documented schema. |

Error messages never contain the bearer token, submitted source, or raw error
pages. Structured error codes are preserved as stable strings.

## Retry policy

- Only idempotent `GET` calls are retried: health, job state, report, and rules.
- `POST /v1/scans`, `POST /v1/jobs`, and `POST /v1/scan` are **never** retried.
  A submission that fails after the server accepted it must be reconciled by the
  caller, never blindly repeated.
- Retries are bounded by `max_retries` (default 2, maximum 5) and apply only to
  transport errors, timeouts, and statuses `408`, `429`, `500`, `502`, `503`,
  `504`. A bounded `Retry-After` header is honored; otherwise delay grows
  exponentially from `retry_backoff` (50 ms) up to `max_retry_delay` (2 s).
- Set `max_retries=0` to turn retries off entirely.

## Safety defaults

- HTTPS required; plain HTTP only for loopback hosts (useful for the mock
  server tests). Credentials, query strings, fragments, and control characters
  in the base URL are rejected.
- The token is sent only as a `Bearer` header, validated before each request,
  and refreshed for each request when a callable is supplied. Redirects are
  refused so it cannot be forwarded to another host.
- Bounded: 30 s request timeout, 1 MiB request cap, 10 MiB response cap,
  bounded polling, bounded retries, and locally validated job ids, file names,
  rule ids, and scan inputs.
- No runtime dependencies and no network access on import.

## Develop

```
python -m unittest discover -s tests -v
```

The tests run against a real loopback HTTP server and use no external
packages. The repository-wide documentation link gate is:

```
python tools/check_docs.py
```
