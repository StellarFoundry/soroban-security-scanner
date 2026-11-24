# Corpus Licensing and Provenance Policy

This document defines the provenance and licensing requirements for third-party
contracts and fixtures included in the test and regression corpus.

## Purpose

The security scanner tests detectors against both synthetic test cases and real-world
smart contracts. Including third-party code without clear licensing and origin records
creates legal and distribution risks. This policy ensures the regression corpus remains
fully publishable, auditable, and compatible with open source distribution under the
MIT license.

## Scope

This policy applies to all third-party contract samples and test fixtures added to
the repository under `fixtures/third-party/`.

Every entry in `fixtures/third-party/<entry>/` must include a `PROVENANCE.toml`
manifest at the root of its directory.

## Required fields

Each `PROVENANCE.toml` file must define the following fields:

| Field | Type | Description |
|---|---|---|
| `license` | string | An approved SPDX license identifier. Must be from the allowed licenses list below. |
| `source_url` | string | Canonical HTTPS URL where the source code originated (e.g. GitHub repository URL). |
| `expected_findings` | string | Relative path to an expected-findings manifest located within the entry directory. |

Example `PROVENANCE.toml`:

```toml
license = "MIT"
source_url = "https://github.com/example-org/example-soroban-contract"
expected_findings = "expected.toml"
```

## Compatible licenses

Only permissive, open-source licenses compatible with the repository's MIT license
are permitted:

- `MIT`
- `Apache-2.0`
- `BSD-2-Clause`
- `BSD-3-Clause`
- `ISC`
- `Unlicense`
- `CC0-1.0`

Any entry with an incompatible license (including copyleft licenses such as GPL or AGPL),
an unknown license, or a missing license is rejected. If the licensing terms of a third-party
contract cannot be verified unambiguously, the entry must not be added to the corpus.

## Expected findings manifest

The file referenced by `expected_findings` (e.g. `expected.toml`) must:
- Exist within the entry directory (paths containing `..` or absolute paths are rejected).
- Document the known or verified findings for the contract.
- Never guess or fabricate findings. When behavior is uncertain or unverified, that ambiguity
  must be explicitly documented.

## Enforcement

The policy is automatically enforced in CI via tests in
`crates/soroban-scan-core/tests/corpus_provenance.rs`.

The test runs as part of `cargo test` and checks:
1. Every directory in `fixtures/third-party/` has a valid `PROVENANCE.toml`.
2. The `license` is present and matches an allowed SPDX identifier.
3. The `source_url` is a valid `https://` URL.
4. The `expected_findings` file exists within the entry directory.
5. Rejection of missing provenance, incompatible licenses, missing source URLs, and broken manifest paths.
# Corpus licensing and provenance policy

The regression corpus must stay publishable. First-party fixtures are
synthetic and covered by the repository license. Any contract copied from a
third party is a **third-party entry** and must carry provenance.

## Where entries live

Third-party entries live under `fixtures/third-party/<entry>/`. Each entry
directory must contain a `PROVENANCE.toml`:

```toml
license = "Apache-2.0"                              # SPDX identifier
source_url = "https://github.com/org/repo/blob/<commit>/contract.rs"
expected_findings = "expected.toml"                 # path inside the entry
```

| Field | Requirement |
| --- | --- |
| `license` | Required. An SPDX identifier from the allow-list below. |
| `source_url` | Required. An `https://` URL; pin a commit or tag where possible. |
| `expected_findings` | Required. Relative path to an existing manifest in the entry directory (no `..`, not absolute). |

## Compatible licenses

`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unlicense`, `CC0-1.0`.

Entries with any other license (including copyleft such as GPL/AGPL), an
unknown license, or no license are **rejected**. Missing information is never
guessed: if provenance is ambiguous, the entry is not added.

## Expected findings

The manifest lists the findings the scanner is expected to report for the
entry. Record only what is verified; if the outcome is uncertain, state that in
the manifest rather than inventing findings.

## Enforcement

`cargo test` (and therefore CI) runs
`crates/soroban-scan-core/tests/corpus_provenance.rs`, which fails when any
entry under `fixtures/third-party/` has a missing or invalid `PROVENANCE.toml`.
The validator itself is tested against fixtures in
`fixtures/provenance-checks/`.
