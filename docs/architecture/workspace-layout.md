# Workspace layout and module dependency map

This document is the map for placing code in the scanner workspace. It lists
both crates, every top-level module in `soroban-scan-core`, the intended
dependency direction, and the modules that form the public API.

The module table is checked by
[`crates/soroban-scan-core/tests/module_map.rs`](../../crates/soroban-scan-core/tests/module_map.rs),
so adding a `pub mod` without documenting it fails the test suite.

## Workspace

```text
soroban-scan-core            soroban-scan-cli
  (library, no I/O policy)     (binary: clap, files, exit codes)
          ^                            |
          |                            |
          +------ depends on ----------+

The core never depends on the CLI. The CLI is the only crate that writes
reports to stdout/files and translates errors into exit codes.
```

| Crate | Path | Role | Public API |
| ----- | ---- | ---- | ---------- |
| `soroban-scan-core` | `crates/soroban-scan-core` | Deterministic discovery, parsing, rule evaluation, baselines, and rendering. No network access by default. | Library API |
| `soroban-scan-cli` | `crates/soroban-scan-cli` | `soroban-scan` binary: argument parsing, config loading, output files, paging, and exit codes (`0/1/2/3`). | Binary only |

## Core module dependency directions

Dependencies point **downward** in this map. A module may use the modules below
it; it must not reach upward into a higher layer. `report` and `baseline` are
leaves with respect to the analysis pipeline: they consume finished findings and
never influence rule evaluation.

```text
                         +----------------+
                         |  cli (binary)  |
                         +--------+-------+
                                  |
        +-------------------------+-------------------------+
        |                         |                         |
     project                   engine                    report
        |                         |                         |
   +----+----+              +-----+-----+             +-----+-----+
   |         |              |           |             |           |
discovery manifest       registry     rules        finding     severity
   |         |              |           |             |           |
   +----+----+              +-----+-----+             +-----+-----+
        |                         |                         |
      model                  context/rule                category/confidence
        |                         |
        +------------+------------+
                     |
                   error
```

`config`, `soroban`, `source`, `suppression`, and `ai` sit alongside the
pipeline: `config` feeds discovery/engine/report, `source` feeds `project` and
`context`, `soroban` feeds `project`/`source`, `suppression` feeds `engine`, and
`ai` is optional and advisory.

## Top-level modules (`soroban-scan-core`)

| Module | Responsibility | May depend on |
| ------ | -------------- | ------------- |
| `error` | `ScanError` and I/O/parse/config/baseline constructors. Foundation for fallible APIs. | Nothing in the crate. |
| `severity` | Ordered `Severity` enum, parsing, aliases, and gate comparison. | Nothing in the crate. |
| `confidence` | Ordered `Confidence` enum and parsing. | Nothing in the crate. |
| `category` | `Category` enum and parsing. | Nothing in the crate. |
| `model` | Serializable project/manifest/diagnostic data model. | Nothing in the crate. |
| `finding` | `Finding`, `SourceLocation`, fingerprints, identity, and sort keys. | `category`, `confidence`, `rule`, `severity`. |
| `fingerprint` | Configurable fingerprint strategies, including the backward-compatible default and path-independent mode. | `finding`. |
| `rule` | `Rule` trait and `RuleMetadata`. | `category`, `confidence`, `context`, `finding`, `severity`. |
| `registry` | Registration, lookup, and deterministic metadata ordering for rules. | `category`, `rule`. |
| `config` | Layered `ScanConfig` and validation; repository config is untrusted input. | `ai`, `category`, `confidence`, `severity`. |
| `manifest` | Syntactic `Cargo.toml` parsing (no execution or fetching). | `error`, `model`. |
| `discovery` | Deterministic, symlink-safe filesystem traversal, exclude globs, and opt-in counting of unsupported source kinds. | `error`, `unsupported`. |
| `frontend` | Bounded parser frontend trait and the default Rust frontend. | `discovery`, `error`, `project`. |
| `detection` | Language and project-type evidence; incomplete evidence is marked weak. | `frontend`, `model`, `soroban`, `source`. |
| `target` | Static Cargo target analysis and target-scoped dependency filtering. | `discovery`, `model`. |
| `sdk_matrix` | Supported Soroban SDK range, verified matrix, and `SDK-001` warnings. | `model`. |
| `unsupported` | Bounded `SYNTAX-001` diagnostics for source languages the frontend cannot analyze. | `model`. |
| `source` | `syn` parsing, spans, module paths, crate-root membership, contract evidence, suppressions. | `error`, `imports`, `model`, `soroban`. |
| `imports` | Best-effort per-file `use` import map and path canonicalization. | Nothing in the crate. |
| `project` | Orchestrates discovery, manifest loading, source parsing, Soroban classification, detection evidence, SDK matrix warnings, and optional target analysis. | `detection`, `discovery`, `error`, `manifest`, `model`, `sdk_matrix`, `soroban`, `source`, `target`, `unsupported`. |
| `soroban` | Soroban evidence and project classification; never executes contracts. | `model`. |
| `context` | Read-only `AnalysisContext` passed to rules, with a per-source/per-function memoized fact cache (interior mutability is used only for memoization; results stay deterministic and file-scoped). | `model`, `rules::util`, `source`. |
| `analysis` | Bounded, data-only taint vocabulary and propagation (`analysis::taint`) plus `TYPE-001` unresolved-type diagnostics (`analysis::types`). | `imports`, `model`, `rules::util`, `source`. |
| `rules` | Built-in detectors, rule metadata validation, and shared analysis helpers. | `category`, `confidence`, `context`, `finding`, `rule`, `severity`, `source`. |
| `engine` | Runs enabled rules, collects/sorts/deduplicates findings, applies suppressions and baselines, and loads projects through the frontend trait. | `config`, `context`, `error`, `finding`, `frontend`, `model`, `registry`, `suppression`. |
| `suppression` | Inline `ignore` directives and source ranges. | `finding`-adjacent data only. |
| `baseline` | Fingerprint baselines, JSON/TOML parsing, merge/prune, unknown-rule diagnostics. | `error`, `finding`, `model`, `registry`, `severity`. |
| `report` | Terminal, JSON, SARIF, Markdown, HTML, and GitHub renderers. | `config`, `engine`, `finding`, `model`, `registry`, `rule`, `severity`. |
| `correlation` | Deterministic, bounded related-finding links shared between JSON and SARIF; ambiguity is recorded, never guessed. | `finding`. |
| `redaction` | Opt-in hashing of selected report fields at render time; fingerprints stay intact. | `baseline`, `engine`, `finding`. |
| `pack` | Rule pack manifest parsing, detached signature verification, keyrings, and rotation/revocation. | `config`, `error`. |
| `policy` | Policy document parsing, validation, and deterministic evaluation. | `config`, `error`, `model`. |
| `monorepo` | Bounded, symlink-safe Cargo project discovery and include/exclude/changed-file path filtering for monorepo scans. | `discovery`, `error`. |
| `ai` | Optional, advisory assistance; deterministic engine remains authoritative. | `category`, `finding`, `rule`, `severity`. |
| `api_auth` | Framework-independent bearer token parsing and verification for API integrations. | Nothing in the crate. |
| `corpus` | Read-only detector fixture, documentation, and must-trigger coverage reporting. | `registry`. |
| `telemetry` | Opt-in, bounded telemetry and crash-event payloads with no source text or paths. | `config`, `engine`, `error`, `model`, `severity`. |
| `service` | Transport-agnostic scan API adapter and bounded job storage for an embedding service. No listener or network access. | `api_auth`, `config`, `engine`, `error`, `registry`, `report`. |

## Subsystem submodules

| Module path | Responsibility |
| ----------- | -------------- |
| `ai::cache` | Bounded, deterministic LRU cache for advisory assistance. |
| `ai::http` | Opt-in provider transport; compiled only with the `ai-http` feature. |
| `ai::redaction` | Deterministic redaction of credential-like text before assistance. |
| `service::api` | Transport-independent request/response mapping, bearer checks, and a synchronous worker hook. |
| `service::jobs` | Thread-safe job lifecycle, count and payload caps, and terminal-job retention. |
| `report` | Single renderer module (`report::render`, `render_*` helpers). |
| `rules::*` | One module per detector (for example `rules::missing_authorization`), plus `rules::util` for shared syntax helpers and `rules::validation` for metadata/docs checks. |
| `analysis::taint` | Data-only source/sink descriptors and bounded propagation into auth subjects and transfer amounts. |
| `analysis::types` | Bounded `TYPE-001` diagnostics for unresolved and ambiguous type names. |
| `rules::test_support` | Test-only helpers for detector unit tests. |

Adding a component normally means adding a `pub mod` here, a row in the table,
and (for detectors) a rule module under `rules/`, documentation in
`docs/rules/detectors/`, and corpus fixtures.

## Public API

All top-level modules are declared `pub` so the CLI, tests, and downstream
tooling can share the model. The **stable library surface** intended for
external consumers is narrower:

- `VERSION`, `TOOL_NAME`, `version_string()`
- `config` (`ScanConfig`, `DiscoveryOptions`)
- `project` (`load`, `load_project`, `load_files`)
- `engine` (`scan`, `scan_source_str`, `ScanOutcome`)
- `registry` (`RuleRegistry`, `Rule`)
- `report` (`render`, `OutputFormat`)
- `baseline` (`Baseline`, `compare`, `serialize`/`parse`)
- `finding`, `model`, `severity`, `confidence`, `category`, `rule`

Modules such as `api_auth`, `corpus`, `discovery`, `policy`, `manifest`, `source`, `soroban`, `context`,
`suppression`, `rules`, and `ai` are public for testing and contributor use.
Changing their signatures is allowed in a `0.x` release but should be called out
in `CHANGELOG.md`.

## Dependency rules

1. `soroban-scan-core` must not depend on `soroban-scan-cli`.
2. No module may perform network access except the opt-in `ai::http` feature.
3. Rules receive read-only context and may not mutate project state or perform
   I/O.
4. `report` and `baseline` must not be called by rules; they run after the
   deterministic engine has produced findings.
5. New dependencies must satisfy [ADR-0005](adr/0005-dependency-justification-policy.md).

Rules 1, 3 and 4 are enforced by
[`crates/soroban-scan-core/tests/dependency_boundaries.rs`](../../crates/soroban-scan-core/tests/dependency_boundaries.rs).
The test parses the `Cargo.toml` manifests and every `use crate::...` path in
the core crate, and fails on a forbidden edge such as `engine -> report` or a
core reference to `soroban_scan_cli`.

## Further reading

- [Architecture overview](overview.md)
- [Determinism contract](adr/0003-determinism-contract.md)
- [Rule development](../rules/README.md)
- [Security model](../security/security-model.md)
