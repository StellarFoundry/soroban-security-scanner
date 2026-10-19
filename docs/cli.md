# CLI Reference

The `soroban-scan` binary provides deterministic security analysis for Soroban
and Rust projects.

```text
soroban-scan <COMMAND>
```

| Command | Purpose |
| ------- | ------- |
| `scan` | Scan a directory or file for findings. |
| `rules` | List available security rules. |
| `explain <RULE-ID>` | Explain a rule in detail. |
| `version` | Print the scanner name and version. |
| `init` | Write a starter configuration file. |
| `config show` / `config validate` | Inspect or validate configuration. |

---

## `scan`

```text
soroban-scan scan [PATH]... [OPTIONS]
```

`PATH` defaults to the current directory and may be repeated to scan several
roots in one run.

| Option | Description |
| ------ | ----------- |
| `--format <terminal\|json\|sarif\|markdown\|github>` | Output format (default `terminal`). |
| `--output <FILE>` | Write the report to a file instead of stdout. |
| `--min-severity <LEVEL>` | Only report findings at or above this severity. |
| `--min-confidence <LEVEL>` | Only report findings at or above this confidence. |
| `--max-findings <N>` | Report at most N findings after sorting; the exit gate is unaffected and the report states how many were omitted. |
| `--exclude <GLOB>` | Exclude a glob relative to the scan root (repeatable). |
| `--exclude-tests` | Skip items gated behind `#[cfg(test)]` and files in test directories. |
| `--config <FILE>` | Use a specific configuration file. |
| `--no-config` | Ignore discovered configuration and use built-in defaults (mutually exclusive with `--config`). |
| `--files-from <FILE>` | Read a newline-separated list of files to scan (relative to `PATH`). |
| `--stdin-filename <NAME>` | Scan a single source read from stdin, using `NAME` as its logical path. |
| `--disable <RULE>` | Disable a rule by id (repeatable). |
| `--rule <RULE>` | Run only the given rule(s) (repeatable). |
| `--fail-on <none\|info\|low\|medium\|high\|critical>` | Failure threshold (default `high`). |
| `--baseline <FILE>` | Compare against a baseline; gate applies to new findings only. |
| `--write-baseline <FILE>` | Write current findings as a baseline and exit. |
| `--new-only` | With `--baseline`, report only new findings. |
| `--incremental` | With `--baseline`, do not report resolved findings. |
| `--guidance` | Print labeled offline guidance for findings (see [ai.md](ai.md)). |
| `--quiet`, `-q` | Compact output; suppresses the header. |
| `--verbose`, `-v` | Include diagnostics (see [diagnostics.md](diagnostics.md)). |
| `--pager <auto\|never\|always>` | Page long terminal reports through `$PAGER` (default `auto`); never affects JSON/SARIF/Markdown/GitHub output. |
| `--color <auto\|always\|never>` | Colorize terminal output (default `auto`). Machine formats never contain ANSI escapes. |

### Inline suppressions

Source comments of the form `// soroban-scan: ignore SS-XXX -- reason`
suppress a single finding at that location. Suppressed findings are excluded
from the `--fail-on` gate but never dropped from the report: terminal, JSON,
SARIF and Markdown output all list them together with the directive that
suppressed them. See [Inline Suppressions](suppressions.md).

### Excluding test code

`--exclude-tests` removes the most common source of noise in one step:

- Items gated behind `#[cfg(test)]` (including entire `#[cfg(test)] mod tests`
  blocks) are pruned before analysis.
- Directories named `tests` are skipped during discovery.
- Production code is never excluded; `#[cfg(not(test))]` items are kept.

```bash
soroban-scan scan ./contracts --exclude-tests
```

### GitHub workflow annotations

`--format github` emits one GitHub Actions workflow command per finding, with
the file, line, optional column/end position, a title, and a message:

```text
::error file=src/lib.rs,line=42,col=9,title=SS-001: State-changing entry point without caller authorization::SS-001: State-changing entry point without caller authorization — ...
```

Severity maps to `error` (critical/high), `warning` (medium), or `notice`
(low/info). All user-controlled text is escaped according to GitHub's
workflow-command rules, so scanned paths or source text cannot inject commands.

### Scanning multiple paths

Pass more than one path to scan several roots in a single run:

```bash
soroban-scan scan contracts/alpha contracts/beta --format json
```

- Every root is scanned with the same configuration, discovered once from the
  current directory.
- Findings, diagnostics, and suppressions from all roots are merged, sorted,
  and de-duplicated into one report with a single exit code.
- Locations are prefixed with the path as given (relative to the current
  directory), so `contracts/alpha/src/lib.rs` and `contracts/beta/src/lib.rs`
  stay unambiguous.
- Each path must live inside the current directory; a path that escapes it
  (including one containing `..`) is a usage error (exit code `2`).
- `--files-from` accepts exactly one `PATH`.

### Bounding report size

Large scans can produce thousands of findings. `--max-findings N` keeps the
first N findings **after the deterministic sort** and adds an explicit notice
with the number omitted:

```bash
soroban-scan scan ./contracts --max-findings 50
```

- Truncation is explicit in every format: terminal and Markdown print
  `N more finding(s) not shown`, GitHub emits a `::notice::`, and JSON/SARIF
  include a `truncation` object with `shown`, `total`, and `omitted`.
- The `--fail-on` gate is evaluated against **all** findings before truncation,
  so a bounded report cannot turn a failing scan into a passing one.
- `--write-baseline` always records every finding; the limit only affects
  rendered reports.

### Long output and paging

Very large terminal reports can flood the console. When output goes to a
terminal and reaches 64 KiB, `--pager auto` (the default) sends it through
`$PAGER` (falling back to `less -R`, or `more` on Windows) so it can be scrolled
and searched.

- Paging never applies to `--format json`, `sarif`, `markdown`, or `github`;
  machine output is always written verbatim.
- When stdout is **not** a terminal (a pipe or a redirect such as
  `soroban-scan scan . > report.txt`), nothing is paged — the full report is
  streamed to the pipe.
- `--pager never` disables paging; `--pager always` forces it for terminal
  output.
- If the pager cannot be launched, the report is written directly.
- The threshold can be overridden with `SOROBAN_SCAN_PAGE_THRESHOLD` (bytes; `0`
  disables automatic paging).

### Color output

`--color auto` (the default) uses ANSI colors only when stdout is an
interactive terminal and `NO_COLOR` is not set. `--color never` is useful for
logs and snapshots; `--color always` is an explicit override for tools that
preserve ANSI escapes.

Colors apply only to the human-readable `terminal` format. JSON, SARIF,
Markdown, and GitHub annotations never contain ANSI escapes, even when
`--color always` is passed. When `--output <FILE>` is used, `auto` stays
plain; `always` still colors terminal-format output written to the file.

### GitHub Actions annotations

`--format github` emits one workflow annotation per finding:

```text
::error file=src/lib.rs,line=42,title=SS-001%3A Missing authorization::SS-001: Missing authorization — storage write without require_auth
```

Severity maps to `error` (critical/high), `warning` (medium), or `notice`
(low/info). Paths, titles, and evidence are escaped according to GitHub's
workflow-command rules, so a crafted source path or finding cannot start a new
command or break the workflow step. A finding produces exactly one line.

### Reading from stdin

`--stdin-filename <NAME>` scans a single Rust source read from standard input,
without requiring it to exist on disk. `NAME` is the logical path recorded in
the report, so locations stay stable across the pipe:

```bash
cat src/lib.rs | soroban-scan scan --stdin-filename src/lib.rs --format json
```

- `NAME` must be non-empty and relative, and may not escape the scan root.
- The scan root is the current working directory; configuration is discovered
  there exactly as for a normal scan.
- Reads are capped at 8 MiB. Oversized input fails with exit code `2` rather
  than being truncated, so a runaway pipe cannot exhaust memory.
- `PATH` and `--files-from` cannot be combined with `--stdin-filename`.

### Examples

```bash
# Human-readable scan
soroban-scan scan ./contracts

# JSON for tooling
soroban-scan scan ./contracts --format json --output report.json --fail-on none

# SARIF for GitHub code scanning
soroban-scan scan ./contracts --format sarif --output results.sarif

# Only high and critical findings
soroban-scan scan ./contracts --min-severity high

# A single file
soroban-scan scan ./contracts/src/lib.rs

# Baseline workflow
soroban-scan scan ./contracts --write-baseline .baseline.json
soroban-scan scan ./contracts --baseline .baseline.json --fail-on high
```

See [`baselines.md`](baselines.md) for the baseline workflow, fingerprint
semantics, and incremental scanning.

---

## `rules`

```text
soroban-scan rules [--format terminal|json] [--category CATEGORY] [--min-severity LEVEL] [--search TEXT]
```

Lists the rule catalog. `--search` matches case-insensitively against rule id,
title, description, and category.

## `explain`

```text
soroban-scan explain SS-001 [--format terminal|json|markdown]
```

Prints a rule's description, defaults, remediation, and references.

## `init`

```text
soroban-scan init [PATH] [--force]
```

Writes `soroban-scan.toml`. Refuses to overwrite unless `--force` is given.

## `config`

```text
soroban-scan config show [--config FILE]
soroban-scan config validate [--config FILE]
```

`show` prints the effective configuration as TOML. `validate` checks a
configuration file and verifies that referenced rule ids exist.

---

## Configuration

Configuration is discovered from `soroban-scan.toml` in the scan root or the
current directory, unless `--config` is given or discovery is disabled with
`--no-config`. Command-line options override the file.

```toml
min_severity = "info"
min_confidence = "low"
exclude = ["vendor/**"]
follow_symlinks = false

[rules]
disabled = ["SS-006"]
enabled = []
disabled_categories = ["resource-usage"]
enabled_categories = []
severity_overrides = { "SS-007" = "low" }
confidence_overrides = { }
```

Unknown fields, rule ids, and category names are rejected. Repository-provided
configuration is treated as untrusted data and cannot enable code execution or
network access.

---

## Output formats

- **terminal** — human-readable, grouped listing with remediation.
- **json** — stable structured report (tool, project, stats, effective config,
  findings, diagnostics). `schema_version` identifies the report contract and is
  independent of the tool version. The `effective_config` object records the
  settings used for the scan, excluding environment data and secrets. When
  `--max-findings` omits findings, a `truncation` object reports the counts.
- **sarif** — SARIF 2.1.0 for GitHub code scanning and compatible tools.
- **markdown** — report suitable for pull requests and documentation.
- **github** — GitHub Actions workflow-command annotations (`::error`,
  `::warning`, `::notice`) with escaped paths, titles, and evidence.

## Severity and confidence

Severity: `info`, `low`, `medium`, `high`, `critical`.
Confidence: `low`, `medium`, `high`.

See [`rules/README.md`](rules/README.md) for their exact meaning.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | Success; no findings at or above the failure threshold. |
| `1` | Findings at or above the failure threshold. |
| `2` | Usage error (bad arguments, unknown rule, invalid configuration). |
| `3` | Runtime error (I/O failure, unreadable scan root). |

`--fail-on` controls the threshold for code `1`. The default is `high`, so
medium/low/info findings do not fail a scan unless configured.

## Security notes

- The scanner never executes, builds, deploys, or modifies scanned code.
- No network access is performed.
- Reports never include environment variables or secrets.
- Paths are relativized to the scan root; traversal outside the root is
  rejected.
