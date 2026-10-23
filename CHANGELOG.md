# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Rule panics are isolated per invocation (`RULE-004`), other rules continue,
  and a regression test now proves findings from healthy rules survive (`#103`).
- Rules now execute in ascending rule-id order, so diagnostics and per-rule
  timings are identical across registries with different registration order
  (`#106`).
- Baseline parsing now fails closed on empty, truncated, or corrupted JSON/TOML,
  with the file path and parser position in the error. A truncated baseline
  exits `3` instead of being treated as empty.
- Source parsing strips a leading UTF-8 BOM and normalizes CRLF/CR line endings
  in memory before parsing, so spans stay accurate on Windows-authored files.
  Scanned files are never modified (`#98`).
- Findings from the same rule and file whose inclusive line ranges overlap are
  now collapsed to the earliest, most specific finding. Adjacent spans and
  findings from different rules/files are kept (`#107`).
- Workspace members using `{ workspace = true }` now inherit the workspace
  dependency version, merged features, and default-feature setting while keeping
  `source = workspace` to record the inheritance (`#43`).
- Documentation now states the exact scope of doc-comment capture: only the
  attributes of the inventoried item are joined, a file-level inner comment
  (`//!`) stays on the parsed syntax tree, and an inner comment inside a `mod`
  body is reported on that module.
- The API-stability and release docs no longer claim that the semver check's
  `release-type: minor` allows breaking changes: it relaxes the lints a minor
  release satisfies, while lints that require a major version still fail the
  job.
- The AI privacy document now describes `Finding.fingerprint` as the truncated
  (128-bit) SHA-256 digest it actually is, and the editor-integration spec
  points at `discovery::DiscoveryOptions` instead of `config::DiscoveryOptions`.

### Added

- The README quickstart now lists the four commands needed for a first scan and
  links to Getting Started for the remaining workflows (`#34`).
- Add an editor integration (LSP) spike covering a minimal diagnostics provider,
  core-library reuse, protocol scope, security, testing, and follow-up tasks
  (`#168`).
- Document the optional AI provider data flow, the exact data a provider
  receives, exclusions, retention caveats, and offline alternatives, linked from
  the AI guide (`#86`).
- Function and non-function item inventory entries expose the joined doc
  comments attached to the item (`///`, `/** ... */`, and `#[doc = "..."]`) as
  `doc`, including multiline comments. A file-level inner comment (`//!`) is an
  attribute of the file rather than of an item, so it stays on the parsed
  syntax tree instead of being reported as an item's `doc` (`#46`).
- Every GitHub Actions reference is pinned to an immutable commit SHA with a
  version comment, and Dependabot updates the pins weekly (`#54`).
- `--log-level` emits structured JSON log lines to stderr (disabled by default);
  stdout remains report-only, and logs never include source, secrets or home
  paths (`#92`).
- A CLI test validates a real JSON report against the published
  `docs/integration/report.schema.json` (`#62`).
- Module paths follow external `mod` declarations (`foo.rs` and `foo/mod.rs`)
  and `#[path = "..."]`; targets escaping the crate root are rejected with
  `SOURCE-003` (`#44`).
- A weekly `cargo-mutants` workflow tracks assertion strength for the engine and
  fingerprint modules, with an initial baseline in
  `docs/development/mutation-testing.md` (`#68`).
- Release artifacts now include a CycloneDX SBOM and a Linux binary with GitHub
  build provenance attestation (`#56`).
- A circuit breaker for the optional assistance layer: after
  `ai.failure_threshold` consecutive provider failures (default `3`),
  assistance is disabled for the remainder of the run and `AI-002` is printed.
  The deterministic scan result is unchanged (`#89`).
- Release notes are generated from the matching `CHANGELOG.md` section by
  `tools/release_notes.py`; the publish workflow fails verification when no
  section exists and creates/updates the GitHub release from it (`#91`).
- Add `.github/CODEOWNERS` for the rule engine, security-sensitive core
  modules, security/rule docs, and CI workflows.
- Add a workspace layout and module dependency map, kept in sync with
  `src/lib.rs` by a module-map test.
- Add ADR-0002, recording the severity and confidence methodology and the
  critical+high heuristic restriction.
- Add `--format html`, a single self-contained report with inline CSS, no
  JavaScript or remote resources, and HTML escaping for every source-derived
  value.
- Associate source files with crate roots only after verifying workspace
  membership against `members` globs, and report `CRATE-001` diagnostics for
  ambiguous nested packages instead of guessing.
- Add a crates.io publishing workflow that verifies the `v*` tag against the
  workspace version, publishes `soroban-scan-core` then `soroban-scan-cli` in
  lockstep, and runs `cargo publish --dry-run` in CI.
- Add ADR-0003, the determinism contract: canonical ordering, stable
  fingerprints, forbidden inputs, and the tests that enforce them.
- Add `doctor`, a read-only diagnostics command that reports manifests,
  classification evidence, excludes, effective configuration, and enabled rules.
- Cache the composite Action's `target/` directory, keyed by runner OS, Action
  ref, and `Cargo.lock`, with a graceful cache-miss fallback.
- Add `main-scan.yml` to scan pushes to `main` against the committed baseline and
  upload SARIF; scheduled updates remain reviewable through `baseline-refresh.yml`.
- Add ADR-0005, the dependency justification and review policy.
- `rules --format markdown` emits the rule catalog table used in
  `docs/rules/README.md`, so the documentation table can be generated from the
  registry in CI instead of edited by hand.

- Markdown scan reports now include `Top rules` and `Categories` summary tables,
  counted deterministically and sorted by count then id or name.
- `init --interactive` asks for minimum severity, enabled categories, and exclude
  globs, then writes a valid configuration. Non-interactive `init` is unchanged,
  prompts are suppressed when stdin is not a terminal, and piped answers are
  still supported for tests and scripted setup.
- A security regression issue template captures the rule id, minimal source,
  expected and actual behavior, and the Soroban SDK version, and directs
  confidential reports to the security policy.
- SS-010 "Privileged state change without an event" (low/low): flags privileged
  storage mutations with no `events().publish` call, with a documented key list.
- SS-012 "Unbounded collection growth in an entry point" (medium/low): flags
  `push`/`push_back`/`push_front` after a storage read with no length guard.
- SS-015 "Deprecated Soroban SDK version" (low/medium): manifest-level finding
  compared against the configurable `minimum_soroban_sdk` policy.
- SS-016 "Unbounded data stored in instance storage" (medium/low): flags repeated
  distinct instance-storage keys and collection growth.
- SS-017 "Authorization after state mutation" (medium/medium): flags storage
  mutations that occur before `require_auth`.
- SS-002 now records constructor argument provenance and suppresses findings for
  hardcoded, storage-configured, and current-contract client addresses.
- FAQ (`docs/faq.md`) answering common questions about false positives, CI
  gating, supported versions, and reporting regressions.
- SS-008 now includes a suggested `checked_*` alternative in its evidence and a
  storage-backed positive corpus fixture.
- `--max-findings N` for `scan`: bounds the rendered report after the
  deterministic sort, prints an explicit omitted-findings notice in every
  format, and exposes `truncation` (`shown`, `total`, `omitted`) in JSON and
  SARIF. The `--fail-on` gate still considers every finding.
- SS-014 "Token transfer amount without validation" (medium/low): flags
  `transfer`/`transfer_from` calls whose amount parameter is not compared
  against zero, with documentation, corpus fixtures, and unit tests.
- GitHub pull-request integration now maintains a single sticky scanner comment.
  A hidden HTML marker identifies the comment, so later pushes update it in place
  instead of adding another comment; duplicate marked comments are removed.
  Commenting remains opt-in and is skipped for fork PRs.
- Optional GitHub check run with structured inline annotations from the JSON
  report (`failure`/`warning`/`notice` levels), a pass/fail conclusion, and a
  50-annotation cap. The check run is opt-in, documented, and skipped for fork
  PRs.
- Scheduled baseline refresh workflow that regenerates the committed baseline
  and opens a reviewable pull request. It never pushes to `main` or auto-merges.
- CI matrix over pinned Soroban SDK fixtures (20.5.0, 21.7.7, and 29.0.1), with
  fixture projects, an offline report checker, and updated compatibility
  documentation.
- `--no-config` for `scan`: skip configuration discovery and run with the
  built-in defaults. Useful when debugging, or when scanning an untrusted
  repository that ships its own `soroban-scan.toml`. Mutually exclusive with
  `--config`.
- Inline suppression directives: `// soroban-scan: ignore SS-XXX -- reason`.
  The engine applies detected directives during the scan, keeps suppressed
  findings out of the `--fail-on` gate, and reports every suppressed finding
  and reason in terminal, JSON, SARIF and Markdown output
  (see [docs/suppressions.md](docs/suppressions.md)).
- SS-029 "Public test or debug hook in a contract entry point" (medium/medium):
  name-segment heuristic for backdoor entry points.
- SS-011 "Initialization entry point without a re-initialization guard"
  (high/low): flags initializer-style entry points that write storage without an
  authorization call or a storage existence read.
- Both detectors ship with corpus fixtures, unit tests, and documentation.
- `scan --help` now includes three copy-pasteable examples.
- Scan statistics and JSON output include `files_parsed`, `files_failed`, and
  `files_skipped`, making parse coverage gaps visible.
- Function visibility is exposed as `source::Visibility` (`public`, `crate`,
  `super`, `self`, `inherited`); only true `pub` functions are contract entry
  points, so `pub(crate)` helpers are no longer treated as exported.
- Ineffective severity/confidence overrides emit a `CONFIG-001` diagnostic when
  the target rule is unknown or disabled. `config validate` prints the same
  warnings without failing.

- Baselines now warn with `BASELINE-001` when they reference rule ids that are no
  longer registered.
- `scan --prune-baseline FILE` removes resolved entries with an auditable
  `removed`/`kept` summary.
- `--baseline` is repeatable and merges files by fingerprint deterministically.
- Baselines can be written and read as TOML; reads auto-detect JSON or TOML and
  JSON remains the default.

### Changed

- SS-001 (missing authorization), SS-002 (cross-contract authorization) and
  SS-006 (persistent write without TTL) now follow intra-file helper functions
  (bounded depth, cycle-safe, deterministic) before deciding to report. This
  removes false positives where authorization or TTL management happens in a
  same-file helper; it does not claim cross-file or whole-program analysis.
- Wave documentation points at the `StellarFoundry` organization, which owns
  the repository, instead of the pre-transfer `AyinkxLab` slug: the maintainer
  setup step in [docs/WAVE.md](docs/WAVE.md) and the curated board in
  [docs/WAVE_BOARD.md](docs/WAVE_BOARD.md) no longer name the wrong org.

### Fixed

- Inline suppression detection is no longer confused by a character literal that
  contains a quote (`let quote = '"';`). The quote is part of the literal instead
  of opening a string that swallowed the rest of the file and silently dropped
  every following directive.
- Block comments are tracked with Rust's nesting rules, so a directive that is
  still inside an outer comment (`/* /* */ // soroban-scan: ignore SS-001 */`) is
  no longer honoured.

### Tests

- Expanded the SS-001 and SS-002 negative corpus with argument-bound
  (`require_auth_for_args`) and helper-delegated authorization cases, plus new
  unit tests for the helper path.

### Performance

- Added an end-to-end CLI benchmark (`tools/benchmark.py`) covering discovery,
  parsing, scanning and report generation, plus pathological-input regression
  tests (`crates/soroban-scan-core/tests/performance.rs`).

### Added

- Explicit `schema_version` (`"1"`) in the JSON report, plus a published
  integration contract (`docs/integration/observatory.md` and
  `docs/integration/report.schema.json`) that defines `soroban-scan` as the
  security-analysis subsystem consumed by the Stellar Contract Observatory.

## [0.2.0] - 2026-09-28

### Added

- SS-008 "Unchecked arithmetic in a contract entry point" detector (medium
  severity, low confidence) with positive/negative corpus fixtures, unit tests,
  and documentation. The AST utility layer now records binary `+`, `-`, and `*`
  operations (`rules::util`).

### Documentation

- Dedicated GitHub Action reference (`docs/github-action.md`).
- CI recipes gallery (`docs/ci-recipes.md`).
- Refreshed top-level README with badges, quickstart, the detector table,
  ecosystem links, and maintainership notes.

## [0.1.0] - 2026-09-21

First MVP release. Deterministic, evidence-based security analysis for Stellar
Soroban smart contracts and Soroban-related Rust projects.

### Added

**Core engine**

- Cargo workspace with `soroban-scan-core` (library) and `soroban-scan-cli`
  (binary).
- Deterministic filesystem discovery with symlink safety, ignored directories,
  and exclude globs.
- `Cargo.toml` parsing (package, workspace, dependency tables, workspace and
  target dependencies).
- Evidence-based Soroban classification: `generic_rust`, `likely_soroban`,
  `confirmed_soroban`.
- `syn`-based source parsing with source locations, item/function inventory, and
  contract entry-point detection.
- Pre-parse delimiter-nesting guard that prevents parser stack overflow on
  hostile input.
- Finding model with severity, confidence, category, location, evidence,
  remediation, references, and line-independent fingerprints.
- Rule trait, registry with id validation, and an immutable analysis context.
- Scan pipeline that validates every finding location against the scan root and
  analyzed file set, rejecting fabricated locations and evidence-less findings.
- Scan configuration (rule enable/disable, severity/confidence overrides,
  thresholds, excludes) with strict TOML parsing.

**Detectors**

- SS-001 State-changing entry point without caller authorization.
- SS-002 Cross-contract call without caller authorization.
- SS-003 Unbounded storage iteration in an entry point.
- SS-004 Panic-prone construct in a contract entry point.
- SS-005 Unsafe code in a Soroban contract.
- SS-006 Persistent storage write without TTL management.
- SS-007 Hardcoded Stellar account or contract address.

**CLI and reporting**

- `scan`, `rules`, `explain`, `version`, `init`, and `config show/validate`.
- Terminal, JSON, SARIF 2.1.0, and Markdown output.
- Stable exit codes (0/1/2/3).
- Single-file, directory, and changed-file (`--files-from`) scanning.
- Baselines: `--baseline`, `--write-baseline`, `--new-only`, `--incremental`.

**Integrations**

- Composite GitHub Action.
- Security Scan workflow with SARIF upload to GitHub code scanning.
- PR changed-file workflow with annotations and opt-in comments.

**Assistance**

- Optional, clearly labeled, offline guidance (`--guidance`). Disabled by
  default and fails closed when a provider is unavailable.

**Quality and infrastructure**

- Security regression corpus with positive/negative fixtures per rule.
- Rule-quality validation (metadata and documentation).
- Adversarial test suite (malformed, deep, large, unicode, scale).
- Dependency-free benchmark example with documented baselines.
- CI: formatting, clippy (`-D warnings`), tests on Linux/Windows/macOS, and
  `cargo-deny`.
- Comprehensive documentation: getting started, installation, CLI,
  configuration, rules, baselines, GitHub integration, security model, threat
  model, compatibility, release, upgrading, and audit.

[Unreleased]: https://github.com/AyinkxLab/soroban-security-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AyinkxLab/soroban-security-scanner/releases/tag/v0.1.0
