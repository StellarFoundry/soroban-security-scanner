# Scanner service API (proposed contract)

> **Status: proposed.** This repository does not ship an HTTP server. This page
> defines the contract that the [TypeScript client](../../clients/typescript/README.md)
> targets, so a service (hosted or self-hosted) and its clients can be built
> against the same, reviewable surface. Until a server implements it, treat it
> as a draft.

All requests and responses are JSON. All endpoints require
`Authorization: Bearer <token>`. The API is versioned by path prefix (`/v1`).

## Endpoints

| Method and path | Purpose | Success |
| --------------- | ------- | ------- |
| `POST /v1/scans` | Submit sources for scanning. | `202` with `{ "id", "status" }` |
| `GET /v1/scans/{id}` | Get scan status. | `200` with `{ "id", "status", ... }` |
| `GET /v1/scans/{id}/report` | Fetch the report of a finished scan. | `200` with a report |

### Submit a scan

```json
{
  "sources": [{ "path": "src/lib.rs", "content": "..." }],
  "options": { "fail_on": "high" }
}
```

- `sources` is required, 1 to 5000 files. Each `path` is relative, uses `/`,
  and does not contain `..`. Submitted code is only analyzed, never built or
  executed.
- `options.fail_on` is optional (`none`, or a severity).
- The response is `{ "id": "<scan id>", "status": "queued" }`. Scan ids match
  `[A-Za-z0-9._-]{1,128}`.

### Scan status

`status` is one of `queued`, `running`, `succeeded`, `failed`. The response may
also carry `created_at`, `updated_at` (RFC 3339 strings) and, when `failed`, an
`error` object (see below).

### Report

`GET /v1/scans/{id}/report` returns the JSON report described by
[`report.schema.json`](report.schema.json) (`schema_version` `"1"`). It returns
`409` with error code `scan_not_finished` until the scan has `succeeded`.

## Errors

Non-2xx responses carry:

```json
{ "error": { "code": "unauthorized", "message": "human-readable text", "details": {} } }
```

`code` is a stable machine-readable string, `message` is for humans, and
`details` is optional. Error bodies must never echo credentials.

## Security expectations

- HTTPS only. Plain HTTP is acceptable only for loopback during local testing;
  the client enforces this.
- Tokens are sent only in the `Authorization` header, never in URLs, and are
  never logged. Servers should not redirect authenticated requests; the client
  refuses to follow redirects.
- Servers should bound request size, scan time, and report size. The client
  defaults to 10 MiB for requests and responses and a 30 second request timeout.
