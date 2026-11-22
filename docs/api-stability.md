# `soroban-scan-core` public API stability

Consumers embedding the scanner may rely on the **stable** surface below.
Everything else is **unstable** and may change in any release.

## Stable

- `engine` entry points for scanning source, manifests, and loaded projects.
- `config` (`ScanConfig`, rule selection, thresholds, excludes, suppressions).
- `finding`, `model`, `severity`, `confidence`, and `category` value types.
- `report` renderers and output format parsing.
- `rule`, `registry`, and `validation` extension points for custom rules.

Breaking changes to these items require a major version bump. Additive changes
may ship in minor releases. The stable surface is listed in `lib.rs` rustdoc and
is enforced by the `api_stability` integration test.

## Unstable

- `api_auth` (framework-independent API bearer authentication), `source`, `project`,
  `discovery`, `manifest`, `suppression`, `soroban`, and
  `rules` internals.
- `detection` (language and project-type evidence).
- `frontend` (the parser frontend boundary and the default Rust frontend).
- `target` (static Cargo target analysis).
- `sdk_matrix` (supported Soroban SDK range and `SDK-001` warnings) and
  `unsupported` (bounded `SYNTAX-001` diagnostics for other languages).
- `imports` (best-effort, per-file `use` resolution), `ai`, `baseline`,
  `compare`, `correlation`, `context`, `error`, `fingerprint`, `pack`, `policy`,
  `corpus`, `redaction`, `service`, and `telemetry` support modules.
- `status_gate` (the policy-driven pull request status-gate record).
- The `analysis`/pipeline implementation details and any `pub(crate)` item.
- Internal utility modules (`rules::util`, `test_support`).

These may be refactored without a major bump. They are public only to support
the scanner's own crates and tests; downstream code should not depend on them.

## Enforcement

The `api_stability` test checks that every top-level `pub mod` is classified in
this document as stable or unstable, and that stable modules remain documented.

CI also runs [`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks)
on every pull request, scoped to `soroban-scan-core`, comparing the branch
against the latest `v*` release tag. While the crate is pre-1.0, the check uses
`release-type: minor`. That relaxes the lints a minor release satisfies, but it
does **not** relax lints that require a major version: `cargo-semver-checks`
still exits non-zero and reports `Summary semver requires new major version`
for those, and the job still fails. A breaking change to the stable surface
therefore needs a deliberate version bump even while the crate is pre-1.0 (see
[`development/release.md`](development/release.md)). Once 1.0 ships, the
release type should be tightened.
