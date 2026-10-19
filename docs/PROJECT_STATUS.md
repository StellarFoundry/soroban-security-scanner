# Project Status

This file is the authoritative progress tracker for the Soroban Security Scanner.
It is updated after every completed task so that a future session can resume
without ambiguity.

**Last updated:** 2026-09-21

**Repository:** https://github.com/StellarFoundry/soroban-security-scanner

**Default branch:** `main`

**Current phase:** Release and Contributor Backlog

---

## Phase overview

| Phase | Title | Status |
| ----- | ----- | ------ |
| 1 | Foundation and Architecture | Complete |
| 2 | Source Parsing and Project Intelligence | Complete |
| 3 | Security Analysis Engine | Complete |
| 4 | Initial Soroban Security Detectors | Complete |
| 5 | Rule Quality and Research Infrastructure | Complete |
| 6 | CLI and Reporting | Complete |
| 7 | Baselines, Incremental Scanning and CI | Complete |
| 8 | GitHub and Developer Integrations | Complete |
| 9 | Developer Experience | Complete |
| 10 | Advanced Analysis and Optional AI | Complete |
| 11 | Production Hardening, Documentation and Release | Complete |

**Release:** `v0.1.0` (see [`CHANGELOG.md`](../CHANGELOG.md)).

---

## Completed tasks

### Phase 1 — Foundation (complete)

- [x] Repository created under `AyinkxLab` (since migrated to the
  `StellarFoundry` organization).
- [x] Cargo workspace: `soroban-scan-core` (lib), `soroban-scan-cli` (bin).
- [x] Core `ScanError` type and version helpers.
- [x] CLI bootstrap exposing `soroban-scan version`.
- [x] Governance docs: README, LICENSE, CONTRIBUTING, CODE_OF_CONDUCT, SECURITY,
      CHANGELOG.
- [x] Architecture overview and ADR-0001.
- [x] Security model and threat model.
- [x] Rule documentation and contributor roadmap.
- [x] CI workflow, issue templates, PR template, pre-commit, cargo-deny.

### Phase 2 — Source Parsing and Project Intelligence (complete)

- [x] Serializable project metadata model (`Project`, `Manifest`, `Dependency`,
      `Diagnostic`, `ProjectKind`).
- [x] Deterministic filesystem discovery with symlink safety and exclude globs.
- [x] `Cargo.toml` parsing (package, workspace, dependencies, workspace and
      target-specific dependencies).
- [x] Evidence-based Soroban classification: `generic_rust`, `likely_soroban`,
      `confirmed_soroban`.
- [x] `syn`-based source parsing with span locations, function/impl/trait/item
      inventory, module paths, and contract entry-point detection.
- [x] Graceful degradation: malformed manifests and unparseable sources become
      diagnostics, not crashes.
- [x] Fixtures: `generic-rust`, `soroban-likely`, `soroban-confirmed`.
- [x] Integration test asserting deterministic metadata output.

### Phase 3 — Security Analysis Engine (complete)

- [x] Severity model (`info`..`critical`) with stable ordering and parsing.
- [x] Confidence model (`low`, `medium`, `high`).
- [x] Category model (authorization, storage, arithmetic, ...).
- [x] `SourceLocation` and `Finding` models with stable, line-independent
      fingerprints for baselines.
- [x] `RuleMetadata` + `Rule` trait; rules observe an immutable context.
- [x] `RuleRegistry` with id validation and duplicate rejection.
- [x] `AnalysisContext` exposing project, sources, functions, and contract entry
      points.
- [x] `ScanConfig`/`RulesConfig` (enable/disable, severity/confidence overrides,
      minimum thresholds, excludes) with strict TOML parsing.
- [x] Engine pipeline: run enabled rules, relativize and validate every location
      against the scan root and analyzed file set, reject rule-fabricated
      locations and evidence-less findings, apply overrides and filters,
      de-duplicate, and sort deterministically.

### Phase 4 — Initial Soroban Security Detectors (complete)

Thirteen detectors, each with metadata, remediation, positive/negative fixtures,
tests, and documentation under `docs/rules/detectors/`:

- [x] SS-001 State-changing entry point without caller authorization (high/medium).
- [x] SS-002 Cross-contract call without caller authorization (high/low).
- [x] SS-003 Unbounded storage iteration in an entry point (medium/low).
- [x] SS-004 Panic-prone construct in a contract entry point (low/medium).
- [x] SS-005 Unsafe code in a Soroban contract (medium/high).
- [x] SS-006 Persistent storage write without TTL management (low/low).
- [x] SS-007 Hardcoded Stellar account or contract address (medium/low).
- [x] SS-008 Unchecked arithmetic in a contract entry point (medium/low).
- [x] SS-009 Insecure randomness derived from ledger state (medium/low).
- [x] SS-011 Initialization entry point without a re-initialization guard (high/low).
- [x] SS-013 Cross-contract call before state update (high/low).
- [x] SS-014 Token transfer amount without validation (medium/low).
- [x] SS-029 Public test or debug hook in a contract entry point (medium/medium).

Supporting work:

- [x] AST utility layer (`rules::util`) extracting calls, macros, strings, and
      `unsafe` facts; contract entry-point discovery.
- [x] Public in-memory scanning API (`engine::scan_source_str`,
      `engine::synthetic_loaded`).
- [x] Security regression corpus under `fixtures/corpus/` with a data-driven
      integration test over all rule ids.
- [x] Adversarial test: malformed source produces diagnostics, not panics.

### Phase 5 — Rule Quality and Research Infrastructure (complete)

- [x] Rule metadata validation (`rules::validation`): id shape, description
      length, remediation, references, and rejection of `critical` + `high`
      combinations for heuristics.
- [x] Registry validation and documentation validation (every rule must have
      `docs/rules/detectors/<ID>.md`).
- [x] Rule-quality integration tests: metadata validity, docs presence, corpus
      presence, per-rule selection isolation, deterministic metadata.
- [x] Adversarial test suite: empty/whitespace/comment-only sources, deep
      nesting, very long lines, unicode identifiers, 2,000 entry points, and
      repeated-scan byte-identity.
- [x] **Security hardening:** added a pre-parse delimiter-nesting guard after
      discovering that deeply nested input could overflow the parser stack
      (a denial-of-service risk on untrusted input).
- [x] Dependency-free benchmark example with documented methodology and
      baseline (`docs/development/benchmarks.md`).
- [x] Rule template (`docs/rules/TEMPLATE.md`) and contributor guide
      (`docs/contributors/writing-rules.md`).

### Phase 6 — CLI and Reporting (complete)

- [x] Reporting layer in core: terminal (full + compact), JSON, SARIF 2.1.0, and
      Markdown renderers, with tests validating structure.
- [x] `scan` command: directory or single-file scanning, format selection,
      file output, min severity/confidence, excludes, rule enable/disable,
      `--fail-on` threshold, quiet/verbose.
- [x] `rules` command with category and severity filters.
- [x] `explain <RULE-ID>` command (terminal/JSON/Markdown).
- [x] `init` command writing a documented config template.
- [x] `config show` and `config validate` commands.
- [x] Strict config loading with CLI override support and unknown-rule detection.
- [x] Stable, documented exit codes (0/1/2/3).
- [x] [`docs/cli.md`](cli.md) reference and README usage update.
- [x] 10 black-box CLI integration tests.

### Phase 7 — Baselines, Incremental Scanning and CI (complete)

- [x] Baseline format (`baseline.rs`): line-independent fingerprints, sorted
      deterministic entries, version validation, and untrusted-input parsing.
- [x] Baseline comparison: new, existing, and resolved findings.
- [x] CLI baseline flags: `--baseline`, `--write-baseline`, `--new-only`,
      `--incremental`. The failure gate considers only new findings when a
      baseline is supplied.
- [x] Incremental scanning via single-file/subset scans with resolved reporting
      disabled.
- [x] `examples/clean-contract` (passes the gate) and
      `examples/vulnerable-contract` (intentional findings).
- [x] GitHub Actions `security-scan.yml` workflow with SARIF upload.
- [x] Cross-platform machine output: paths serialize with forward slashes.
- [x] [`docs/baselines.md`](baselines.md) and CLI reference updates.
- [x] Baseline CLI integration tests.

### Phase 8 — GitHub and Developer Integrations (complete)

- [x] Composite GitHub Action (`action.yml`) with inputs for path, format,
      output, fail-on, baseline, files-from, and extra args.
- [x] `--files-from` CLI option for changed-file analysis, with traversal
      rejection.
- [x] `pr-scan.yml` workflow: changed-file analysis, high/critical annotations,
      SARIF generation, guarded code-scanning upload, and opt-in PR comments.
- [x] SARIF upload compatibility exercised structurally; code-scanning upload
      guarded for fork pull requests.
- [x] Documented permissions, fork-PR safety, baseline synchronization, and an
      opt-in issue-creation pattern in [`docs/github-integration.md`](github-integration.md).
- [x] CLI integration tests for `--files-from` and traversal rejection.

### Phase 9 — Developer Experience (complete)

- [x] `rules --search` (case-insensitive over id, title, description, category)
      and `--category` filtering.
- [x] Documentation index (`docs/README.md`).
- [x] Getting Started, Installation, Configuration, and Troubleshooting guides.
- [x] README documentation index.
- [x] Human-readable terminal/Markdown reports with severity summaries
      (Phase 6), remediation guidance, and `explain` for every rule.
- [x] Example clean and vulnerable projects (Phase 7).
- [x] Rule template and writing-rules guide (Phase 5).
- [x] CLI tests for rule search and invalid category.

### Phase 10 — Advanced Analysis and Optional AI (complete)

- [x] Optional assistance layer (`ai` module): `Assistant` trait, `AiConfig`
      (disabled by default), and a labeled offline `RuleGuidance` assistant that
      derives text only from existing findings and rule metadata.
- [x] Fail-closed behavior: enabling assistance without a bundled provider (or
      naming an unknown provider) errors clearly; the deterministic scan still
      runs.
- [x] CLI `--guidance` prints labeled offline guidance to stderr so machine
      output stays clean.
- [x] [`docs/ai.md`](ai.md) documents guarantees, the network policy for future
      providers, and what AI must never do.
- [x] Config template and configuration reference include the `[ai]` section.
- [x] Unit and CLI tests for disabled-by-default, fail-closed, and labeling.

### Phase 11 — Production Hardening, Documentation and Release (complete)

- [x] Corrected the Rust support policy: removed an unverifiable `rust-version`
      pin and documented the real policy in [`compatibility.md`](compatibility.md).
- [x] Compatibility matrix: Rust, OS, Soroban SDK, machine-readable formats,
      exit codes.
- [x] Release process ([`development/release.md`](development/release.md)) and
      upgrade guidance ([`development/upgrading.md`](development/upgrading.md)).
- [x] Production-readiness audit ([`development/audit.md`](development/audit.md))
      with honest Verified/Partial/Planned statuses.
- [x] Documentation link checker (`tools/check_docs.py`); 42 Markdown files
      checked, no broken relative links.
- [x] Full local gate: fmt, clippy (`-D warnings`), 143 tests, release build,
      CLI smoke tests, SARIF generation.
- [x] CI verified green on GitHub (Format, Clippy, Test on Linux/Windows/macOS,
      Dependency audit) and the Security Scan workflow (with SARIF upload).
- [x] Workflows updated to `actions/checkout@v5`.
- [x] Tagged `v0.1.0` and published a GitHub release.

---

## Verified environment

- OS: Windows (win32), shell PowerShell 5.1.
- Rust: 1.97.1, toolchain `stable-x86_64-pc-windows-gnu` (local directory override).
- crates.io reachable.
- `cargo build`, `cargo test`, `cargo fmt --check`, `cargo clippy -D warnings` pass.

## Test summary

- Unit tests: 107
- Integration tests: 36 (CLI 18, corpus 3, rule quality 5, adversarial 6,
  project detection 4)
- Total: 143 (all passing)

## CI status

- GitHub Actions `CI` workflow has passed on every push (format, clippy, tests
  on Linux/Windows/macOS, and `cargo-deny`).
- GitHub Actions `Security Scan` workflow passed, including SARIF upload to
  GitHub code scanning.
- `PR Security Scan` is authored and will run on the next pull request.

## Performance

Release throughput on a developer machine: ~2,500-2,800 entry points/s
(~700 KB/s of source). See `docs/development/benchmarks.md`.

## Known limitations

- Detectors are syntactic; no type resolution. SS-001 and SS-006 follow
  intra-file helper functions (bounded depth) but there is no whole-program or
  cross-file data flow.
- SS-002, SS-003, SS-006, SS-007, SS-008, SS-009, SS-011, SS-013, SS-014, SS-029 are
  heuristic and low/medium confidence.
- The `PR Security Scan` workflow has not yet run (no pull request has been
  opened); its underlying commands are covered by local tests.
- Only thirteen detectors exist; the roadmap covers many more.

## Architecture decisions

- [ADR-0001: Rust core with Python supporting tooling](architecture/adr/0001-rust-core-python-tooling.md)

## Examples

A real, compilable example suite lives under [`examples/`](../examples/README.md).
Each example is a standalone crate targeting `soroban-sdk` 28, excluded from the
workspace, and built in CI (`examples.yml`).

| Example | Kind | Scanner result |
| ------- | ---- | -------------- |
| `clean-contract` | Soroban vault | 0 findings |
| `token` | Soroban fungible token | 0 findings |
| `escrow` | Soroban escrow | 0 findings |
| `vault` | Soroban pausable vault | 0 findings |
| `stellar-classic` | Classic Stellar address tooling | 0 findings (generic Rust) |
| `vulnerable-contract` | Intentionally vulnerable | SS-001, SS-002, SS-004, SS-006, SS-007 |

Compilation was verified locally with `cargo check`/`cargo test` for all six
examples, and compilation is enforced in CI on changes to `examples/**`. The
`Security Scan` workflow gates the clean examples with `--fail-on high` and
uploads SARIF for the vulnerable example. As a result, classic Stellar tooling
(for example `stellar-strkey`) is no longer classified as Soroban.

## Contributor backlog

An expanded backlog of **170 open issues** is tracked on GitHub. It is authored
from structured definitions in `tools/backlog/` and created with
`tools/create_backlog.py` (idempotent, dry-run by default). The full manifest is
[`docs/ISSUE_BACKLOG.md`](ISSUE_BACKLOG.md), regenerated with
`tools/generate_manifest.py`.

Breakdown by phase:

| Phase | Count |
| ----- | ----- |
| phase-1 Foundation | 11 |
| phase-2 Parsing | 16 |
| phase-3 Engine | 17 |
| phase-4 Detectors | 30 |
| phase-5 Rule quality | 21 |
| phase-6 CLI and reporting | 14 |
| phase-7 Baselines and CI | 11 |
| phase-8 GitHub integrations | 12 |
| phase-9 Developer experience | 13 |
| phase-10 Advanced analysis and AI | 10 |
| phase-11 Hardening and release | 15 |
| **Total** | **170** |

Breakdown by complexity: 40 `difficulty/trivial`, 107 `difficulty/medium`,
23 `difficulty/high`.

Every issue includes problem, why it matters, scope, technical guidance,
acceptance criteria, tests, security considerations, dependencies, complexity,
definition of done, and wave contribution guidelines (assignment, `Closes #`,
local gate, example commit message). No artificial, duplicate, or padding issues
were created; three oversized umbrellas were split into cycle-sized issues and
closed with links to their children.

## Wave readiness

- Every open issue carries a `difficulty/*` label (trivial / medium / high).
  The point value itself (100 / 150 / 200) is assigned in the Drips Wave
  maintainer dashboard when issues are added to a Program.
- Issue bodies include assignment and PR conventions via
  `tools/wave_guidelines.py`; existing issues were backfilled with
  `tools/apply_wave_guidelines.py`.
- Maintainer review commitments (48h response, 72h review decision), Wave
  assignment/review flow, and rollover behavior are documented in
  [`docs/WAVE.md`](WAVE.md) and [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- `good-first-issue` items (12 open) are available for new contributors; 38 open
  issues are labeled `soroban`.
- A curated first-Wave set with a bounded budget (20 issues, 2,650 points) is in
  [`docs/WAVE_BOARD.md`](WAVE_BOARD.md).
- Repository topics are set for discoverability (stellar, soroban, security,
  sarif, static-analysis, rust, smart-contracts, cli, and more).
- [`CONTRIBUTORS.md`](../CONTRIBUTORS.md) and a public [`ROADMAP.md`](ROADMAP.md)
  are available.
- **Traction (honest):** 1 external contributor and 1 merged external PR so far.
- **Not yet done (human step):** install the Drips Wave GitHub App on the
  `StellarFoundry` org and apply this repository to the Stellar Wave Program.
  Approval is decided by the program organizers. See `docs/WAVE.md` for the checklist.

## Next task

None. The roadmap in this document is complete for v0.1.0; continuing work is
tracked in the GitHub issue backlog and [`docs/ISSUE_BACKLOG.md`](ISSUE_BACKLOG.md).
