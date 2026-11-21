# Scan API Authentication

The scan API is an opt-in adapter (the scanner CLI itself does not listen on a port). Any HTTP API adapter must require bearer authentication before accepting scan requests. It must fail closed if the API configuration or token is absent.

The adapter can load its dedicated TOML configuration with `ApiAuthConfig::from_toml`:

```toml
[api]
# Keep this value in a protected, untracked configuration file.
bearer_token = "replace-with-a-random-secret"
```

`ApiAuthConfig::authenticate` accepts an `Authorization` header value and returns success only for a matching `Bearer` token. An unset token returns `NotConfigured`; missing, malformed, and incorrect credentials return the same `Unauthorized` error. The API config input is limited to 64 KiB, and the token is bounded to 4096 bytes and must use bearer-token characters. The comparison processes a fixed number of bytes and does not exit early on a mismatch.

The token is omitted from serialization and redacted from `Debug`; errors do not contain credentials. Do not log incoming authorization headers or configured tokens. Configure secrets through a protected deployment file or secret manager, and do not commit them.

The guard is intentionally independent of a web framework so the API server can apply it before request-body parsing or scan work. Authentication behavior is tested by:

```bash
cargo test -p soroban-scan-core --test api_auth
```
