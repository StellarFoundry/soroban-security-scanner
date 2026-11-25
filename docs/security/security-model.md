# Security Model

This document states the guarantees the scanner makes and, equally important, the
guarantees it does **not** make.

## What the scanner does

- Reads source files and manifests from a target directory.
- Parses Rust source statically.
- Applies deterministic rules and emits findings with evidence.
- Writes reports to stdout or to user-specified files.
- Optionally reads a baseline file to classify findings as new/resolved.

## What the scanner never does

- Never requests, stores, or uses private keys or wallet credentials.
- Never signs or submits transactions.
- Never deploys contracts.
- Never executes scanned code or contract binaries.
- Never runs `cargo build`/`cargo run` on the target.
- Never installs dependencies or downloads executables.
- Never makes network requests by default.
- Never modifies the scanned repository.
- Never emits secrets or environment variables in reports.
- Never fabricates findings, source locations, or certainty.

## Treating input as hostile

Scanned repositories are untrusted. The scanner:

- Does not follow symlinks outside the scan root by default.
- Applies exclude rules and a scan root boundary.
- Treats repository-provided configuration as untrusted data that cannot grant
  capabilities.
- Handles parser failures gracefully without panicking.
- Bounds resource usage on pathologically large or deeply nested input.

## Network policy

The default build performs **no network access**. The only network-capable code
is the non-default `ai-http` feature, which provides the provider transport in
`crates/soroban-scan-core/src/ai/http.rs`. It enforces:

- An explicit destination allowlist; there is no implicit allow-all mode.
- HTTPS only, with embedded credentials rejected.
- Connect and read timeouts plus a hard response-size limit.
- Manual redirect handling; every redirect target is re-validated.
- SSRF protection: loopback, private, link-local, carrier-grade NAT,
  documentation, multicast, and metadata addresses are denied, including DNS
  answers for allowlisted names.
- Fail-closed behavior: no fallback transport and no partially validated request.
- No source code or secrets are sent off-device without explicit, informed
  consent.

Network access is never enabled by a repository-provided configuration; it
requires building the opt-in feature and naming an allowlisted provider.

## GitHub integration boundary

The GitHub Action, reusable workflow, and helper scripts may use a short-lived
workflow token for the capabilities listed in the
[permission catalogue](../github-integration.md#permissions-summary). Those
capabilities are opt-in, job-scoped, and never available to fork pull requests.
The scanner itself remains offline and read-only: it never reads a token from
the scanned repository, never persists a credential, and never creates a
comment, check, or issue unless the caller explicitly enables that side effect.
Token storage, rotation, and revocation are documented in
[GitHub Integration](../github-integration.md#token-storage-rotation-and-revocation),
and the committed [least-privilege App manifest](../github-app-manifest.yml)
requests no explicit repository permission.

## AI policy

AI is optional and advisory. The deterministic engine remains authoritative.

AI must never:

- Invent findings or source locations.
- Override or suppress deterministic findings.
- Claim certainty without evidence.
- Access secrets or execute actions.
- Modify code automatically.

AI-generated text is always clearly labeled as AI-generated.

## Reporting secret exposure

If the scanner itself leaks a secret or environment variable in its output, treat
it as a security vulnerability and report it per [`../../SECURITY.md`](../../SECURITY.md).
