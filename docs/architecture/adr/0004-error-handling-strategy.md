# ADR-0004: Error-handling strategy

- **Status:** Accepted
- **Date:** 2026-10-22
- **Deciders:** AyinkxLab maintainers

## Context

The scanner runs on untrusted input from arbitrary repositories. Its error
handling must satisfy two competing requirements:

1. **Resilience.** A single malformed file, an unsupported macro, or a rule
   bug must not abort the entire scan. Downstream consumers (CI, GitHub code
   scanning) need a result even when some sources are unprocessable.
2. **Honest exit codes.** The CLI uses stable exit codes that CI scripts rely
   on. A miscategorised error would mislead callers into treating a configuration
   mistake as a successful scan, or a successful scan as a runtime failure.

Until now the distinction between library errors (`ScanError`), CLI errors
(`CliError`), and non-fatal scan diagnostics has lived only in code. New
contributors adding rules or parsing features lacked a single reference for
when to `return Err(…)`, when to emit a `Diagnostic`, and why the engine must
never panic.

## Decision

### 1. Two-layer error model

The scanner uses two distinct error types that reflect ownership:

**`ScanError`** (`soroban-scan-core/src/error.rs`) is the library error type.
It is returned by operations that genuinely cannot continue: configuration that
is structurally invalid, a path that was rejected for security reasons, a
baseline file that cannot be parsed. Variants today:

| Variant | When to use |
| ------- | ----------- |
| `Io` | An I/O operation failed for a specific path (unreadable directory, permission error on the scan root). |
| `Parse` | Reserved for use in library-internal helpers where a parse failure must propagate to a higher-level caller that will decide whether to abort or downgrade. Not used in the main scanning pipeline (see §2 below). |
| `Config` | The configuration file is structurally invalid or contains a value that cannot be represented. |
| `Baseline` | A baseline file is malformed or its format is incompatible with the current schema. |
| `UnknownRule` | A rule id referenced in configuration does not exist. |
| `UnsafePath` | A path was rejected by the security policy (escapes the scan root, contains `..`, or is not relative). |

**`CliError`** (`soroban-scan-cli/src/main.rs`) is the command-level error type.
It exists only in the binary crate and maps directly to exit codes:

| Variant | Exit code | Meaning |
| ------- | --------- | ------- |
| `Usage` | 2 | Bad arguments, unknown rule id in flags, invalid configuration supplied by the user. |
| `Runtime` | 3 | I/O failure on the scan root, unreadable output path, or any `ScanError` that prevents the scan from starting or completing. |

`ScanError` maps to `CliError::Runtime` via the `runtime()` helper. The CLI
never returns `CliError::Runtime` for something the user could fix by changing a
flag — that belongs in `CliError::Usage`.

### 2. Diagnostics are preferred over errors for per-file failures

Any condition that affects one source file but not the overall scan is reported
as a `Diagnostic` rather than a `ScanError`. Diagnostics carry a stable code,
a severity level, a human-readable message, and an optional path. The scan
continues after emitting a diagnostic.

**Parser failures** are the canonical example. When `syn` cannot parse a
source file, `source.rs` wraps the error into a `PARSE-001` diagnostic
(`DiagnosticCode::ParseFailed`) at `DiagnosticLevel::Warning` and continues
loading the remaining files. The file is still present in the source set but
its AST is empty, so rules that visit AST nodes produce no findings for it.
This prevents a deliberately malformed file from silencing the entire scan.

The fixture `fixtures/projects/parse-error/src/lib.rs` contains intentionally
invalid Rust and is used to verify that parse failures appear as `PARSE-001`
diagnostics and do not abort the scan.

The table below lists the diagnostic codes that apply to file-level failures:

| Code | Variant | Trigger |
| ---- | ------- | ------- |
| `PARSE-001` | `ParseFailed` | `syn` could not parse the file. |
| `SOURCE-001` | `SourceTooLarge` | File exceeds the size limit and was skipped. |
| `SOURCE-002` | `SourceUnreadable` | File could not be read from disk. |
| `SOURCE-003` | `SourceModulePathRejected` | A `#[path]` declaration escapes the crate root. |
| `CRATE-001` | `AmbiguousCrateRoot` | The file's crate root could not be determined unambiguously. |
| `MANIFEST-001` | `ManifestUnreadable` | A `Cargo.toml` could not be read or parsed. |

Diagnostic codes are part of the public contract. Once released, a code keeps
its meaning and is never reused. Tooling may classify or suppress diagnostics
by code without parsing the human-readable message.

### 3. No-panic rule for the scanning pipeline

The core scanning pipeline — discovery, parsing, rule execution, and reporting —
must not panic on any input, including adversarially constructed repositories.
Two mechanisms enforce this:

**Rule isolation.** The engine wraps each rule's `check` call in
`std::panic::catch_unwind`. If a rule panics, the engine emits a `RULE-004`
diagnostic (`DiagnosticCode::RulePanicked`) and discards that rule's findings
for the current scan. The remaining rules run normally.

**No `unwrap` / `expect` on untrusted data.** Code on the scanning path must
not call `unwrap()` or `expect()` on values derived from scanned source
(file contents, AST nodes, manifest fields). Use `?`, `if let`, or `match`
instead. This applies to rules, source loading, discovery, and reporting.
Code that operates on compiler-internal or previously validated data (for
example, rule metadata that is constructed in code, not parsed from input) may
use `expect` with an explanatory message.

**Rule execution budget.** When a time budget is configured
(`rules.rule_time_budget_ms`), a rule that exceeds it receives a `RULE-005`
diagnostic (`DiagnosticCode::RuleTimeBudgetExceeded`) and its findings are
discarded. This prevents a pathological input from hanging CI.

### 4. Decision guide for contributors

When writing new rules or changing the scanning pipeline, apply this decision
tree:

```
Can this operation affect only one file?
  YES → emit a Diagnostic and continue.
  NO  → does it prevent the scan from producing any output?
    YES → return ScanError (library) or CliError (CLI).
    NO  → emit a Diagnostic and continue.
```

Additional rules:

- A rule must never call `panic!`, `unwrap()`, or `expect()` on any value
  derived from scanned source. The engine's `catch_unwind` is a last resort,
  not a license to panic.
- A new `ScanError` variant is appropriate only if the condition prevents the
  scan from starting or requires the caller (CLI or test harness) to make a
  decision about how to proceed.
- A new `DiagnosticCode` requires updating `docs/diagnostics.md` in the same
  pull request. The code string (`PARSE-001`, `RULE-004`, …) is stable once
  released.
- `CliError::Usage` vs `CliError::Runtime`: if the user can fix it by changing
  a flag or a configuration file, it is `Usage`; if it is an environmental
  failure the user cannot directly control, it is `Runtime`.

## Alternatives considered

- **Abort the scan on any parser failure.** Rejected: a hostile repository
  could silence every finding by including one syntactically invalid file.
  Making parser failures non-fatal is a direct safety requirement.
- **Use a single `Error` enum for both the library and the CLI.** Rejected:
  a single type conflates different concerns (library contracts vs CLI exit
  codes) and makes it harder to test the library in isolation.
- **Propagate panics instead of catching them.** Rejected: a panic in a rule
  would crash the entire scan, discarding all findings and returning a
  misleading exit code. Isolation limits the blast radius to one rule.
- **Use `eprintln!` instead of `Diagnostic` for file-level warnings.** Rejected:
  `eprintln!` output is not machine-readable, not stable, and not visible in
  JSON or SARIF reports. `Diagnostic` with a stable code is the right vehicle.

## Consequences

- Scans complete and produce findings even when some source files are
  unprocessable, which is the safe behavior for untrusted input.
- The CLI exit codes remain stable and unambiguous, supporting CI scripts that
  distinguish configuration mistakes from runtime failures.
- Rule authors have a clear policy: no panics, no `unwrap` on untrusted data,
  and per-file problems go through `Diagnostic`.
- Adding a new `DiagnosticCode` is a public-contract change and requires
  documentation alongside the code.

## References

- [`ScanError`](../../../crates/soroban-scan-core/src/error.rs)
- [`CliError` and exit codes](../../../crates/soroban-scan-cli/src/main.rs)
- [`DiagnosticCode` (model)](../../../crates/soroban-scan-core/src/model.rs)
- [Parser failure → diagnostic (source.rs)](../../../crates/soroban-scan-core/src/source.rs)
- [Rule isolation via `catch_unwind` (engine.rs)](../../../crates/soroban-scan-core/src/engine.rs)
- [Parse-error fixture](../../../fixtures/projects/parse-error/src/lib.rs)
- [ADR-0003: Determinism contract](0003-determinism-contract.md)
- [Security model](../../security/security-model.md)
- [Threat model](../../security/threat-model.md)
