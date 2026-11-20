# Soroban SDK compatibility matrix fixtures

Each supported directory is a minimal contract pinned to one verified
`soroban-sdk` release. The CI `sdk-matrix` job runs the rule suite against every
supported fixture and asserts that the project is classified as a confirmed
Soroban contract, that the pinned SDK version is detected, and that the expected
detectors still fire.

The supported fixtures intentionally share the same source. They exercise APIs
that are stable across the supported range (`#[contract]`, `#[contractimpl]`,
persistent storage, `symbol_short!`) while containing a known SS-001 and SS-008
finding.

| Fixture | Pinned SDK | Status |
| ------- | ---------- | ------ |
| `soroban-sdk-20` | 20.5.0 | Supported (oldest verified line) |
| `soroban-sdk-21` | 21.7.7 | Supported (last v21 release) |
| `soroban-sdk-29` | 29.0.1 | Supported (current release) |
| `soroban-sdk-19` | 19.0.0 | Unsupported; must emit `SDK-001` |
| `soroban-sdk-30` | 30.0.0 | Unsupported; must emit `SDK-001` |

The supported range is `>=20.5.0, <30.0.0`. Releases outside it are still
scanned, but the scanner warns that rule coverage may be inaccurate. These are
scanner fixtures, not production contracts. Do not add real secrets or real
account addresses.
