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
