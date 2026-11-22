# soroban-scan-client

A small, dependency-free, typed TypeScript client for the soroban-scan service
API ([proposed contract](../../docs/integration/api.md)): authenticate, submit a
scan, poll it, and fetch the report. Ships ESM and CommonJS builds with type
declarations. Requires Node 18+ (global `fetch`) or a custom `fetch`.

~~~ts
import { SorobanScanClient } from "soroban-scan-client";

const client = new SorobanScanClient({
  baseUrl: "https://scan.example.com",
  token: process.env.SCAN_TOKEN!, // or an async function returning a token
});

const report = await client.scan(
  { sources: [{ path: "src/lib.rs", content: source }], options: { fail_on: "high" } },
  { intervalMs: 1000, timeoutMs: 120_000 },
);

for (const finding of report.findings) {
  console.log(finding.rule_id, finding.severity, finding.location?.file);
}
~~~

Step by step: `submitScan`, `getScan`, `waitForScan`, `getReport`. Errors are all
`SorobanScanError` subclasses: `ApiError` (HTTP status and error code),
`ScanFailedError`, `PollTimeoutError`, `ClientTimeoutError`,
`ResponseTooLargeError`, `InvalidResponseError`, `InvalidBaseUrlError`.

## Safety defaults

- The base URL must be HTTPS (plain HTTP only for loopback) and must not contain
  credentials, a query string or a fragment.
- The token is sent only as a bearer header, is validated (no whitespace or
  control characters), and is never included in error messages.
- Redirects are refused, so the token cannot be forwarded to another host.
- Bounded: 30 s request timeout, 10 MiB request and response caps, bounded
  polling interval and total polling time, and scan ids and source paths are
  validated before any request is sent.
- No runtime dependencies. `typescript` is a dev dependency only. The package is
  marked `private` until the maintainers decide how to publish it.

## Develop

~~~
npm install
npm test     # clean, build ESM + CJS, run tests against a local mock server
~~~
