# soroban-scan-client

A small, dependency-free, typed TypeScript client for the soroban-scan scan API
documented in [docs/service-api.md](../../docs/service-api.md): authenticate with
a bearer token, submit Rust source, poll the job, and read its report. Ships ESM
and CommonJS builds with type declarations. Requires Node 18+ (global `fetch`)
or a custom `fetch`.

The repository provides the scan service as an in-process, transport-agnostic
module (`soroban_scan_core::service`); it is not an HTTP server. This client
talks to a deployment that exposes that module's `ScanApi` over HTTP.

~~~ts
import { SorobanScanClient } from "soroban-scan-client";

const client = new SorobanScanClient({
  baseUrl: "https://scan.example.com",
  token: process.env.SCAN_TOKEN!, // or an async function returning a token
});

const report = await client.scan(
  { source: contractSource, file: "lib.rs" },
  { intervalMs: 1000, timeoutMs: 120_000 },
);

for (const finding of report.findings) {
  console.log(finding.rule_id, finding.severity, finding.location?.file);
}
~~~

## Endpoints covered

| Method | API call | Client method |
| ------ | -------- | ------------- |
| `POST /v1/scans` | Queue a job (`source`, optional `file`). | `submitScan` |
| `GET /v1/jobs/{id}` | Job state; `report` once `completed`, `error` once `failed`. | `getJob` |
| (polling) | Wait for `completed`. | `waitForJob` |
| (convenience) | Report of a finished job. | `getReport`, `scan` |

Job states are `queued`, `running`, `completed`, `failed`. Errors are all
`SorobanScanError` subclasses: `ApiError` (HTTP status and the API's error code,
for example `unauthorized`, `invalid_request`, `payload_too_large`, `store_full`,
`authentication_not_configured`), `ScanFailedError`, `PollTimeoutError`,
`ClientTimeoutError`, `ResponseTooLargeError`, `InvalidResponseError`,
`InvalidBaseUrlError`.

## Safety defaults

- The base URL must be HTTPS (plain HTTP only for loopback) and must not contain
  credentials, a query string or a fragment.
- The token is sent only as a bearer header, is validated (no whitespace or
  control characters), and is never included in error messages.
- Redirects are refused, so the token cannot be forwarded to another host.
- Bounded: 30 s request timeout, 1 MiB request cap (the service default payload
  limit), 10 MiB response cap, bounded polling interval and total polling time.
  Job ids and `file` names are validated before any request is sent.
- No runtime dependencies. `typescript` is a dev dependency only. The package is
  marked `private` until the maintainers decide how to publish it.

## Develop

~~~
npm install
npm test     # clean, build ESM + CJS, run tests against a local mock server
~~~
