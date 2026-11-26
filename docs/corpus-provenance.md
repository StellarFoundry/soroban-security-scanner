# Corpus Licensing and Provenance Policy

The regression corpus must stay publishable. First-party fixtures are
synthetic and covered by the repository license. Any contract copied from a
third party is a **third-party entry** and must carry provenance.

## Purpose

The scanner tests detectors against synthetic cases and real-world contracts.
Third-party code creates legal and distribution risks unless its origin and
license are recorded. This policy keeps the corpus auditable and compatible
with open-source distribution under the repository's MIT license.

## Where entries live

Third-party entries live under `fixtures/third-party/<entry>/`. Each entry
directory must contain a `PROVENANCE.toml`:

```toml
license = "Apache-2.0"                              # SPDX identifier
source_url = "https://github.com/org/repo/blob/<40-char-commit>/contract.rs"
source_file = "contracts/contract.rs"                # upstream path
license_file = "../LICENSE"                          # shared license text
expected_findings = "expected.toml"                  # path inside the entry
secret_review = "YYYY-MM-DD: review result"
```

| Field | Requirement |
| --- | --- |
| `license` | Required. An SPDX identifier from the allow-list below. |
| `source_url` | Required. An `https://` URL pinned to a 40-character commit. |
| `source_file` | Required. Upstream path of the copied source. |
| `license_file` | Required. Existing license text shared by the curated entries. |
| `expected_findings` | Required. Relative path to an existing manifest in the entry directory (no `..`, not absolute). |
| `secret_review` | Required. Date and result of the pre-commit secret review. |

## Compatible licenses

`MIT`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Unlicense`, `CC0-1.0`.

Entries with any other license (including copyleft such as GPL/AGPL), an
unknown license, or no license are **rejected**. Missing information is never
guessed: if provenance is ambiguous, the entry is not added.

## Expected findings

The manifest named by `expected_findings` records the findings the scanner
actually reports for each copied source file. It contains:

```toml
schema_version = 1
entry = "example-entry"
verified_with = "soroban-scan 0.2.0; ScanConfig::default; RuleRegistry::with_default_rules"
notes = "Findings generated from the pinned upstream source and reviewed."

[[contracts]]
file = "src/lib.rs"

[[contracts.findings]]
rule_id = "SS-001"
count = 2
severity = "high"
confidence = "medium"
```

Findings are generated from scanner output with:

```text
UPDATE_THIRD_PARTY_EXPECTATIONS=1 cargo test -p soroban-scan-core --test third_party_corpus
```

Review the diff before committing. Never regenerate manifests merely to make
an unrelated test pass. A rule ID, edge, count, severity, or confidence is
never invented. When an upstream construct is ambiguous or unsupported by the
frontend, the ambiguity is recorded in `notes` rather than converted into a
guessed finding.

## Curated real-world entries

The current corpus adds eight contracts from `stellar/soroban-examples`,
pinned to commit `03d42aa6b973dcf3a453a99d0c6a6e8d25a196e2`. All upstream
sources in that commit are Apache-2.0; the full license text is copied to
`fixtures/third-party/LICENSE` and referenced by every `license_file` field.

| Entry | Upstream source |
| --- | --- |
| `soroban-examples-account` | `account/src/lib.rs` |
| `soroban-examples-atomic-swap` | `atomic_swap/src/lib.rs` |
| `soroban-examples-auth` | `auth/src/lib.rs` |
| `soroban-examples-custom-types` | `custom_types/src/lib.rs` |
| `soroban-examples-events` | `events/src/lib.rs` |
| `soroban-examples-increment` | `increment/src/lib.rs` |
| `soroban-examples-liquidity-pool` | `liquidity_pool/src/lib.rs` |
| `soroban-examples-token` | `token/src/contract.rs` |

Before committing, each copied source was reviewed for secrets with bounded
text searches for private keys, mnemonics, credentials, tokens, and long
hex/base64 blobs. No such values were found; the result is recorded in each
`secret_review` field. Public contract addresses and symbolic token variables
in the examples are not secrets.

Ambiguity note: these are intentionally small educational examples, not a
sample of every production Soroban pattern. The expected manifests describe
only findings verified against the pinned sources. Absence of a finding is
not a claim that the corresponding pattern is safe in a different contract.

## Enforcement

`cargo test` runs two checks:

1. `crates/soroban-scan-core/tests/corpus_provenance.rs` fails when any entry
   under `fixtures/third-party/` has a missing or invalid `PROVENANCE.toml`.
2. `crates/soroban-scan-core/tests/third_party_corpus.rs` requires at least
   five entries, verifies the pinned provenance fields, scans every copied
   Rust source, and compares the exact findings to the reviewed manifest.

The provenance validator itself is tested against fixtures in
`fixtures/provenance-checks/`.
