# In-process scan service

The repository ships a library module, `soroban_scan_core::service`, for
embedding the scanner behind a service. It is **not** an HTTP server: the
binary is still CLI-only, the module opens no sockets, and the default build
performs no network access. A deployment supplies its own transport, parsing,
and worker loop.

## What exists

- A transport-agnostic API adapter (`service::api`) that maps plain request and
  response values to a job lifecycle.
- A bounded job store (`service::jobs`) with fixed caps on job count, payload
  size, report size, and retention.
- Bearer authentication for API adapters (`api_auth`), independent of any web
  framework.

No HTTP listener, queue daemon, database, or remote worker exists in this
repository. Passing `ApiRequest` values to `ScanApi::handle` and writing the
returned `ApiResponse` is the caller's transport job.

## API surface

| Method and path | Behavior |
| --------------- | -------- |
| `POST /v1/scans` | Accepts `{"source": "...", "file": "lib.rs"}`. `file` defaults to `input.rs` and must be a plain `.rs` name. Returns `202` with `job_id` and `status: "queued"`. |
| `GET /v1/jobs/{id}` | Returns `202` while queued or running, then `200` with either `report` (completed) or a structured `error` (failed). |

Every request is authenticated first. Missing or wrong credentials return
`401` with `{"error":{"code":"unauthorized",...}}`; an API without a configured
token fails closed with `503 authentication_not_configured`. Unknown routes
return `404 not_found`.

Work is not executed on submission. An embedding worker calls
`ScanApi::run_next()` to process the oldest queued job synchronously and
repeatedly. This keeps the adapter free of threads, timers, and background
state the caller did not ask for.

Submission errors:

| Status | Code | Cause |
| ------ | ---- | ----- |
| `400` | `invalid_request` | Body is not UTF-8 JSON, the schema is wrong, or `file` is unsafe. |
| `413` | `payload_too_large` | Body or source exceeds the job payload cap. |
| `503` | `store_full` | The bounded store is at `max_jobs`. |

The API response never echoes the bearer token or the submitted source.

## Bounds

| Limit | Default | Constant |
| ----- | ------- | -------- |
| Jobs retained in any state | 128 | `DEFAULT_MAX_JOBS` |
| One payload or report | 1 MiB | `DEFAULT_MAX_PAYLOAD_BYTES` |
| Retention of a finished job | 24 hours | `DEFAULT_RETENTION` |

`JobLimits` overrides all three. A zero limit is accepted and rejects all work
of that kind; reject configuration that does not make sense for your service.

Memory is bounded by roughly `max_jobs * max_payload_bytes` for queued and
running jobs, and by the same maximum for finished reports. Error messages are
truncated to `max_payload_bytes` on a UTF-8 boundary.

## Full-store behavior

`JobStore::submit` performs these steps in order:

1. Reject a payload larger than `max_payload_bytes` with
   `PayloadTooLarge { limit }`.
2. Prune finished jobs whose retention elapsed.
3. Reject the submission with `StoreFull { limit }` if the store still holds
   `max_jobs` jobs.

A full store **never evicts a queued or running job** to make room. Callers get
a structured error and may retry after a job finishes and its retention
expires. This prevents accepted work from disappearing without a trace.

`StoreFull` and `PayloadTooLarge` expose stable codes through
`JobStoreError::code`: `store_full` and `payload_too_large`.

## Retention

Retention applies only to terminal jobs (`Completed` or `Failed`). A queued or
running job is never removed, even when it is older than the retention window.
Pruning runs on submission and can also be requested explicitly with
`JobStore::remove_expired`. The scanner stores jobs in memory only; a restart
loses every job.

## Lifecycle

```text
submit -> Queued -> start -> Running -> complete -> Completed
                                      -> fail     -> Failed
```

Only the shown transitions are allowed. `start`, `complete`, and `fail` return
`InvalidTransition` for any other source state, so a worker cannot overwrite a
finished report or mark a queued job complete.

## Embedding example

```rust
use soroban_scan_core::service::jobs::{JobLimits, JobStore};

let store = JobStore::new(JobLimits::default());
let id = store.submit(contract_source)?;
store.start(&id)?;
store.complete(&id, report_json)?;
```

## Tests

The module includes a load-style test that submits 1,000 jobs, verifies the cap
holds for another 1,000 submissions, and checks that every retained job keeps
its state. The API end-to-end suite submits a real fixture, polls the job,
validates the report, and covers authentication and oversized-input failures.
Everything runs offline.

```bash
cargo test -p soroban-scan-core --lib service::
cargo test -p soroban-scan-core --test api_e2e
```

## Related

- [Scan API authentication](api-authentication.md) - the bearer-token guard.
- [Report retention](retention.md) - naming and retention for report files.
- [Architecture](architecture/workspace-layout.md) - module map.
