# Compatibility

## Rust toolchain

- **Policy:** a recent stable Rust toolchain. CI builds and tests on stable for
  Linux (x86_64 and aarch64), Windows, and macOS.
- **Verified with:** Rust 1.99.0.
- **MSRV:** Rust **1.91.0**. Every crate declares `rust-version = "1.91"`, and
  the CI `msrv` job builds and tests the workspace with `--locked` on that exact
  toolchain, so this is the minimum downstream users can rely on.

## Operating systems

| OS | Status |
| -- | ------ |
| Linux x86_64 | Supported (CI tested) |
| Linux aarch64 | Supported (CI tested on `ubuntu-24.04-arm`) |
| macOS | Supported (CI tested) |
| Windows | Supported (CI tested; MSVC and GNU toolchains) |

## Soroban SDK

- **Detection:** version-agnostic. Any `soroban-sdk` (or `soroban-*` /
  `stellar-*`) dependency is recognized, and `#[contract]` / `#[contractimpl]`
  are used to confirm contract projects.
- **Detector targeting:** the built-in detectors model the modern Soroban SDK
  storage and authorization APIs (`env.storage().persistent()/instance()/temporary()`,
  `Address::require_auth`, generated `*Client` constructors). These correspond to
  SDK v20 and later.
- **Verified against fixtures pinned to** `soroban-sdk = "20.5.0"`,
  `"21.7.7"`, and `"29.0.1"` under `fixtures/sdk-matrix/`.

### SDK compatibility matrix

The CI `sdk-matrix` job scans the pinned fixture for each version and asserts
that:

- the fixture is classified as `confirmed_soroban`;
- the pinned version is detected in `project.soroban_sdk_versions`; and
- the SS-001 (missing authorization) and SS-008 (unchecked arithmetic) findings
  are still reported.

| SDK version | Fixture | Status |
| ----------- | ------- | ------ |
| 20.5.0 (oldest supported line) | `fixtures/sdk-matrix/soroban-sdk-20` | Verified |
| 21.7.7 (last v21 release) | `fixtures/sdk-matrix/soroban-sdk-21` | Verified |
| 29.0.1 (current release) | `fixtures/sdk-matrix/soroban-sdk-29` | Verified |

The matrix exercises scanner behavior, not contract compilation. The shared
fixture source deliberately sticks to APIs stable across these releases, so a
failure indicates detector or project-detection drift rather than an SDK build
problem. Run the same check locally after building the scanner:

```bash
soroban-scan scan fixtures/sdk-matrix/soroban-sdk-21 \
  --format json \
  --output sdk-21.json \
  --fail-on none
python tools/check_sdk_matrix.py sdk-21.json --sdk 21.7.7
```

## Machine-readable formats

| Format | Version | Stability |
| ------ | ------- | --------- |
| JSON report | `schema_version: "1"` in current development builds; `0.2.0` and earlier omit the field. | Stable shape; additive changes only within a minor line. |
| SARIF | 2.1.0 | Stable. |
| Baseline file | `version: 1` | Versioned; unsupported versions are rejected. |
| Configuration | schema v0 | Unknown fields are rejected; additive changes are announced. |
| Rule ids | `SS-###` | Permanent and never reused. |

## Exit codes

Stable; see [CLI Reference](cli.md#exit-codes).
