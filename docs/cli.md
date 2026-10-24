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
| `doctor` | Explain project classification, excludes, and effective configuration. |
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
| `--format <terminal\|json\|sarif\|markdown\|html\|github>` | Output format (default `terminal`). |
| `--output <FILE>` | Write the report to a file instead of stdout. |
| `--min-severity <LEVEL>` | Only report findings at or above this severity. |
| `--min-confidence <LEVEL>` | Only report findings at or above this confidence. |
| `--max-findings <N>` | Report at most N findings after sorting; the exit gate is unaffected and the report states how many were omitted. |
| `--exclude <GLOB>` | Exclude a glob relative to the scan root (repeatable). |
| `--exclude-tests` | Skip items gated behind `#[cfg(test)]` and files in test directories. |
| `--include-cfg-test` | Also analyze items gated behind `#[cfg(test)]`, which are skipped by default. |
| `--config <FILE>` | Use a specific configuration file. |
| `--no-config` | Ignore discovered configuration and use built-in defaults (mutually exclusive with `--config`). |
| `--files-from <FILE>` | Read a newline-separated list of files to scan (relative to `PATH`). |
| `--stdin-filename <NAME>` | Scan a single source read from stdin, using `NAME` as its logical path. |
| `--disable <RULE>` | Disable a rule by id (repeatable). |
| `--rule <RULE>` | Run only the given rule(s) (repeatable). |
| `--fail-on <none\|info\|low\|medium\|high\|critical>` | Failure threshold (default `high`). |
| `--baseline <FILE>` | Compare against a baseline (repeatable; files are merged). Gate applies to new findings only. |
| `--write-baseline <FILE>` | Write current findings as a baseline and exit. |
| `--prune-baseline <FILE>` | Rewrite the baseline with only findings present in this scan and print a removal summary. |
| `--baseline-format <json\|toml>` | Baseline output format (default inferred from the file extension, then JSON). Reads auto-detect. |
| `--new-only` | With `--baseline`, report only new findings. |
| `--incremental` | With `--baseline`, do not report resolved findings. |
| `--guidance` | Print labeled offline guidance for findings (see [ai.md](ai.md)). |
| `--quiet`, `-q` | Compact output; suppresses the header. |
| `--verbose`, `-v` | Include diagnostics (see [diagnostics.md](diagnostics.md)). |
| `--timings` | Print per-rule wall-clock time to stderr. Presentation-only: never appears in JSON/SARIF/Markdown/GitHub output and never changes findings, ordering, fingerprints or the exit gate. |
| `--log-level <off\|error\|warn\|info\|debug>` | Emit structured JSON log lines to stderr (default `off`). Stdout stays reserved for the report; logs never include source text, environment values, or absolute home paths. |
| `--pager <auto\|never\|always>` | Page long terminal reports through `$PAGER` (default `auto`); never affects JSON/SARIF/Markdown/GitHub output. |
| `--color <auto\|always\|never>` | Colorize terminal output (default `auto`). Machine formats never contain ANSI escapes. |

### Structured logs

`--log-level` writes one JSON object per line to stderr; it is disabled by
default so existing output is unchanged. Stdout is never touched, so `--format
json` remains machine-parseable.

```bash
soroban-scan scan ./contracts --format json --log-level info > report.json
# stderr:
# {"level":"info","event":"scan.start","roots":1,"stdin":false,...}
# {"level":"info","event":"scan.complete","files_analyzed":12,"findings":3,...}
```

Only counts, rule/format labels, and durations are logged. Scanned source,
environment variables, secrets, and absolute home paths are never logged.

### Per-rule timings

`--timings` writes one line per executed rule to stderr, sorted by rule id:

```
timing: SS-001 0.412 ms (completed)
timing: SS-007 2.871 ms (completed)
```

The status is `completed`, `timed_out` (the rule exceeded
`rules.time_budget_ms`), or `panicked` (isolated by the engine). Timings are
wall-clock measurements, so they intentionally never enter machine-readable
reports; the scan report is byte-identical with or without the flag.

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

### `cfg` attributes and test-gated items

The parser records the raw tokens of every `#[cfg(...)]` attribute on items and
functions (`cfg_attrs` in the inventory), for example `test` or
`feature = "extras"`. Expressions are **not evaluated**: the scanner does not
know which features or targets you build with.

By default, items gated behind `#[cfg(test)]` (including functions inside
`#[cfg(test)] mod tests`) are skipped by every detector, because they are not
shipped in the contract. Only the built-in `test` predicate counts:
`#[cfg(not(test))]` and `#[cfg(feature = "test")]` are treated as production
code, and all other `cfg` code (features, targets) is scanned as usual.
Predicates that merely mention `test` inside `all(...)`/`any(...)` are treated
as test-gated.

Pass `--include-cfg-test` (or set `include_cfg_test = true`) to analyze
test-gated items too. `--exclude-tests` additionally skips `tests` directories
and wins if both are given. Because skipped items are removed before analysis,
they do not appear in the inventory unless `--include-cfg-test` is set.

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

- Paging never applies to `--format json`, `sarif`, `markdown`, `html`, or
  `github`;
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

# Self-contained HTML for sharing with reviewers
soroban-scan scan ./contracts --format html --output report.html

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
soroban-scan rules [--format terminal|json|markdown] [--category CATEGORY] [--min-severity LEVEL] [--search TEXT]
```

Lists the rule catalog. `--search` matches case-insensitively against rule id,
title, description, and category. `--format markdown` emits the same table used
in [`rules/README.md`](rules/README.md), so the docs table can be regenerated
instead of maintained by hand:

```bash
soroban-scan rules --format markdown
```

## `explain`

```text
soroban-scan explain SS-001 [--format terminal|json|markdown]
```

Prints a rule's description, defaults, remediation, and references.

## `init`

```text
soroban-scan init [PATH] [--force] [--interactive]
```

Writes `soroban-scan.toml`. Refuses to overwrite unless `--force` is given.

With `--interactive`, the wizard asks for the minimum severity, the categories
to enable, and exclude globs, then writes only the answers plus the safe
defaults. Prompts are shown only when stdin is a terminal; piped input is still
read, so the flow can be scripted. Without `--interactive`, the documented
starter template is written unchanged.

## `doctor`

```text
soroban-scan doctor [PATH] [--format terminal|json] [--config FILE] [--no-config]
```

Prints the discovered manifests, classification and evidence, source file count,
excludes, effective configuration, and enabled rule ids. See
[Doctor](doctor.md).

## `completions`

```text
soroban-scan completions <bash|zsh|fish|powershell>
```

Prints a shell completion script to stdout. The command is hidden from
`--help`. Examples:

```bash
soroban-scan completions bash > ~/.local/share/bash-completion/completions/soroban-scan
soroban-scan completions zsh  > ~/.zfunc/_soroban-scan
soroban-scan completions fish > ~/.config/fish/completions/soroban-scan.fish
soroban-scan completions powershell >> $PROFILE
```

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
  settings used for the scan, excluding environment data and secrets. `stats`
  includes `files_parsed`, `files_failed`, and `files_skipped` so coverage gaps
  are visible. When `--max-findings` omits findings, a `truncation` object
  reports the counts. The published JSON Schema is
  [`docs/integration/report.schema.json`](integration/report.schema.json); a
  CLI test validates a real report against it on every run.
- **sarif** — SARIF 2.1.0 for GitHub code scanning and compatible tools.
- **markdown** — report suitable for pull requests and documentation. The
  summary includes a severity table, the most frequent rule ids, and the
  categories with the most findings, each sorted deterministically.
- **html** — a single self-contained file with inline CSS, no JavaScript, and no
  remote resources. All source-derived text (titles, evidence, remediation,
  paths, suppressions) is HTML-escaped, so crafted findings cannot inject
  markup. Suitable for sharing with reviewers who do not use a terminal.
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
