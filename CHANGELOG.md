# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
