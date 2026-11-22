# Deploying the scan API adapter

> **Warning:** the in-process scan API is not a hardened public edge. It ships
> no HTTP listener, no TLS, no health endpoint, no persistent storage, and no
> multi-tenant isolation. Treat it as a library that your own trusted service
> wraps, and put an authenticated, TLS-terminating reverse proxy in front of any
> network exposure.

The repository provides `soroban_scan_core::service` as a transport-agnostic
adapter. A deployment supplies the HTTP server, request parsing, worker loop,
health checks, and durable storage. See [In-process scan service](service-api.md)
for the request/response contract and [Scan API authentication](api-authentication.md)
for the credential model.

## Configuration

Build the adapter with an explicit scan configuration and job limits:

```rust
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::service::{
    ApiAuthConfig, JobLimits, RateLimitConfig, ScanApi,
};
use soroban_scan_core::registry::RuleRegistry;

let auth = ApiAuthConfig {
    bearer_token: std::env::var("SOROBAN_SCAN_API_TOKEN").ok(),
};
let limits = JobLimits {
    max_jobs: 128,
    max_payload_bytes: 1024 * 1024,
    retention: std::time::Duration::from_secs(24 * 60 * 60),
};
let config = ScanConfig::from_toml(&std::fs::read_to_string("soroban-scan.toml")?)
    .expect("valid scanner configuration");

let api = ScanApi::with_scan(
    auth,
    limits,
    config,
    RuleRegistry::with_default_rules(),
)
.with_rate_limit(RateLimitConfig::per_window(
    60,
    std::time::Duration::from_secs(60),
));
```

- `ScanApi::with_scan` binds authentication, job limits, scan settings, and the
  rule registry. `ScanApi::new` is the same with default scan settings.
- `ApiAuthConfig::from_toml` loads `[api] bearer_token = "..."` from a protected
  file. An unset token fails closed (`503 authentication_not_configured`).
  Validate the configuration before listening.
- `JobLimits` caps retained jobs, one payload/report size, and retention of
  finished jobs. A zero or nonsensical limit is accepted by the library and
  should be rejected by deployment validation.
- `RateLimitConfig` is opt-in, fixed-window, and keyed per bearer token.
  Authentication runs first, so invalid credentials do not consume budget.
  `RateLimitConfig::default()` allows 60 requests per 60 seconds.

Every authenticated response carries `RateLimit-Limit`, `RateLimit-Remaining`,
and `RateLimit-Reset` headers. A denied request returns `429 rate_limited` with
`Retry-After`. Write these headers to the wire in the embedding transport.

## TLS termination

The adapter never terminates TLS. Run it behind a reverse proxy (for example
Envoy, nginx, or a managed load balancer) that:

1. Listens on HTTPS with a valid certificate.
2. Redirects or rejects plain HTTP.
3. Forwards only the documented paths (`POST /v1/scans`,
   `GET /v1/jobs/{id}`).
4. Passes the `Authorization` header through unchanged and does not log it.
5. Applies request-body size limits before the adapter's own payload cap.

Disable proxy access logs for authorization headers, and do not place the
scanner behind an unauthenticated cache. The adapter still enforces bearer
authentication after TLS termination, so a misconfigured proxy cannot make it
public by accident.

## Storage and durability

`JobStore` is **in memory only**. Restarting the process loses every queued,
running, completed, and failed job. Finished jobs are retained for the
configured window and then pruned; they are never written to disk by this
repository.

If jobs must survive a restart, run a single worker per process and persist
accepted requests and terminal reports in your own durable queue or database.
The adapter does not provide crash recovery, replay, or idempotency keys. Do
not run multiple processes against one logical queue unless your transport adds
that coordination; each `ScanApi` instance has its own store and rate limiter.

## Health checks

No health endpoint exists. The embedding transport must supply liveness and
readiness checks. A useful readiness check is:

1. The reverse proxy is accepting TLS connections.
2. `ApiAuthConfig::validate()` succeeded at startup and a token is configured.
3. The worker loop is running and can call `ScanApi::run_next()`.
4. Optional: the adapter can handle a trivial request without returning
   `503 store_full`.

Health responses should not include the bearer token, job contents, findings,
or configuration secrets. Do not reuse `/v1/scans` as a health check; it
consumes a job slot and, when enabled, a rate-limit budget.

## Minimal local example

The example below is a transport skeleton, not a production server. It uses a
plain TCP listener and no TLS, so bind it to loopback only.

```rust
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use soroban_scan_core::service::{
    ApiAuthConfig, ApiRequest, JobLimits, RateLimitConfig, ScanApi,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth = ApiAuthConfig {
        bearer_token: Some("local-development-token".to_string()),
    };
    auth.validate()?;
    let api = ScanApi::new(auth, JobLimits::default()).with_rate_limit(
        RateLimitConfig::per_window(60, Duration::from_secs(60)),
    );

    let listener = TcpListener::bind("127.0.0.1:8080")?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        let mut buffer = [0u8; 64 * 1024];
        let read = stream.read(&mut buffer)?;
        // Parse the HTTP request line, headers, and body in your transport.
        // Keep only Authorization, method, path, and body.
        let request = ApiRequest {
            method: "POST".to_string(),
            path: "/v1/scans".to_string(),
            authorization: None,
            body: buffer[..read].to_vec(),
        };
        let response = api.handle(&request);
        write!(
            stream,
            "HTTP/1.1 {}\r\n\r\n{}",
            response.status, response.body
        )?;
        // Also run a worker loop elsewhere: while let Some(_id) = api.run_next() {}
    }
    Ok(())
}
```

This skeleton is intentionally incomplete. A real transport must parse HTTP
correctly, enforce its own body limit, run `ScanApi::run_next()` to execute
queued work, and implement health checks.

## Checklist

- [ ] Bearer token loaded from a secret manager or protected file, never logged.
- [ ] `ApiAuthConfig::validate()` checked at startup and missing tokens rejected.
- [ ] `JobLimits` and `RateLimitConfig` set for the expected load.
- [ ] TLS terminated by a reverse proxy; plain HTTP rejected.
- [ ] Authorization headers excluded from proxy and application logs.
- [ ] Health and readiness endpoints supplied by the embedding transport.
- [ ] Durable queue/database added if jobs must survive a restart.
- [ ] No public exposure without authentication and TLS.

## Related

- [In-process scan service](service-api.md) - endpoints, job lifecycle, bounds.
- [Scan API authentication](api-authentication.md) - bearer-token configuration.
- [Rule pack signing](rule-pack-signing.md) - verifying external pack metadata.
- [Architecture](architecture/workspace-layout.md) - module map.
