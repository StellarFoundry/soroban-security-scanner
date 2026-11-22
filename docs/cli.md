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
| `lsp` | Start the editor language server on stdio (see [editors.md](editors.md)). |
| `serve` | Start the opt-in loopback HTTP scan API. |
| `init` | Write a starter configuration file. |
| `doctor` | Explain project classification, excludes, and effective configuration. |
| `compare` | Compare two JSON scan reports by finding fingerprint. |
| `dashboard` | Render a static trend dashboard from several JSON scan reports. |
| `artifact-name` | Print the canonical, deterministic report artifact name. |
| `pack` | Install, list, update, or remove local community rule packs. |
| `config show` / `config validate` | Inspect or validate configuration. |

---

## `serve`

```text
SOROBAN_SCAN_API_TOKEN='replace-with-a-long-random-token' \
  soroban-scan serve [--bind 127.0.0.1:8080] [--config FILE | --no-config]
```

Starts a sequential HTTP/1.1 server bound to loopback only. The token must be
provided through `SOROBAN_SCAN_API_TOKEN`; it is never accepted on the command
line or included in responses. `POST /v1/scans` accepts
`{"source":"...","file":"input.rs"}` (the `file` field is optional) and returns
the standard CLI JSON report. Source/file inputs and HTTP headers are bounded;
requests are processed one at a time. The endpoint only scans submitted source
text and does not access arbitrary filesystem paths. This local integration
server is opt-in and is not intended to be exposed to a network.

Example:

```sh
curl -H "Authorization: Bearer $SOROBAN_SCAN_API_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"source":"pub fn example() {}","file":"input.rs"}' \
  http://127.0.0.1:8080/v1/scans
```

---

## `lsp`

```text
soroban-scan lsp
```

Starts the stdio language server. It speaks JSON-RPC 2.0 with `Content-Length`
framing, performs no network access, and exits when the client sends `exit`.
Supported capabilities are diagnostics (`textDocument/publishDiagnostics`),
full-document sync, and document symbols. See [editors.md](editors.md) for the
VS Code and Neovim setup and the current limitations.

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
| `--mode <soroban\|generic\|auto>` | Project analysis mode (default `soroban`). `generic` is opt-in and skips Soroban-only rules; `auto` uses generic mode only for plain Rust projects. The effective mode is always shown. |
| `--target-analysis` | Read Cargo target configuration and filter target-scoped dependencies (default off). Only wasm32 is understood; unsupported targets are reported. Never builds or executes the project. |
| `--unsupported-syntax` | Report bounded `SYNTAX-001` diagnostics for source files in languages the Rust frontend cannot analyze (default off). Aggregated by language; source text is never read or reported. |
| `--max-findings <N>` | Report at most N findings after sorting; the exit gate is unaffected and the report states how many were omitted. |
| `--redact <FIELD>` | Replace a report field with a stable hash at render time (repeatable; see [Report redaction](#report-redaction)). |
| `--exclude <GLOB>` | Exclude a glob relative to the scan root (repeatable). |
| `--exclude-tests` | Skip items gated behind `#[cfg(test)]` and files in test directories. |
| `--include-cfg-test` | Also analyze items gated behind `#[cfg(test)]`, which are skipped by default. |
| `--config <FILE>` | Use a specific configuration file. |
| `--no-config` | Ignore discovered configuration and use built-in defaults (mutually exclusive with `--config`). |
| `--files-from <FILE>` | Read a newline-separated list of files to scan (relative to `PATH`). |
| `--include-project <GLOB>` | Monorepo filtering: scan only Cargo projects matching `GLOB` (repeatable). See [Monorepo path filtering](#monorepo-path-filtering). |
| `--exclude-project <GLOB>` | Monorepo filtering: skip Cargo projects matching `GLOB` (repeatable); wins over `--include-project`. |
| `--changed-files <FILE>` | Monorepo filtering: scan only Cargo projects that own a file in this list (relative to `PATH`). |
| `--stdin-filename <NAME>` | Scan a single source read from stdin, using `NAME` as its logical path. |
| `--disable <RULE>` | Disable a rule by id (repeatable). |
| `--rule <RULE>` | Run only the given rule(s) (repeatable). |
| `--fail-on <none\|info\|low\|medium\|high\|critical>` | Failure threshold (default `high`). |
| `--sarif-policy <none\|info\|low\|medium\|high\|critical>` | Opt-in SARIF policy annotations on each result; requires `--format sarif`. |
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

### Analysis modes

The default `soroban` mode runs the full rule set. `--mode generic` is opt-in:
it skips every rule that is Soroban-only (all built-in detectors today), so a
plain Rust project never receives Soroban-flavored claims. `--mode auto` applies
generic mode only when the project is classified as `generic_rust`.

The effective mode is printed as `Mode:` in terminal and Markdown reports and
stored as `stats.mode` in JSON. Generic mode also emits a `MODE-001`
informational diagnostic naming the project classification and the number of
rules skipped, so a mode change is never silent. The same setting is available
as `mode = "soroban"` in `soroban-scan.toml`.

### Target analysis

`--target-analysis` is opt-in. It reads, without running Cargo:

- `[lib] crate-type` and `[target.<key>.*]` tables in discovered `Cargo.toml`
  manifests;
- `[build] target` and `[target.<key>]` tables in `.cargo/config.toml` or
  `.cargo/config` (capped at 1 MiB; unreadable or invalid files emit
  `TARGET-003`).

Only `wasm32*` targets are understood. When an explicit target is configured,
dependencies scoped to a different target are removed before rule evaluation,
so a host-only dependency cannot produce a false Soroban dependency finding in
a wasm build. An explicit non-wasm target emits a `TARGET-001` warning saying
that target analysis is unsupported; a detected wasm32 target emits an
informational `TARGET-002`. The scanner never builds, runs, or invokes `cargo`
on the scanned project.

The static result appears in terminal and Markdown output as `Target:` and in
JSON as `stats.target`. The same setting is available as
`target_analysis = true` in `soroban-scan.toml`.

### Unsupported syntax

`--unsupported-syntax` (or `unsupported_syntax = true`) reports when a scan
silently covers less than expected. Only the Rust frontend ships, so files with
recognized non-Rust source extensions (for example `.ts`, `.tsx`, `.sol`,
`.go`, or `.py`) are skipped rather than partially parsed.

- One `SYNTAX-001` warning is emitted per language, with a count — not one per
  file.
- At most 8 language kinds are listed, plus one warning stating how many were
  omitted, so output stays bounded.
- Only file extensions are inspected. Source text is never read, echoed, or
  stored in the diagnostic.
- Known Rust inputs (`Cargo.toml` and `.rs` files) are never flagged.
- The check is off by default.

### Detection manifest

Every report records why a language and project type were selected. Only the
Rust frontend ships today, and the manifest never claims another language. JSON
exposes it as `stats.detection`:

```json
{
  "language": "rust",
  "frontend": "rust",
  "project_type": "confirmed_soroban",
  "confidence": "strong",
  "evidence": [
    { "kind": "manifest", "path": "Cargo.toml", "detail": "Cargo.toml manifest" },
    { "kind": "source", "path": "src/lib.rs", "detail": "1 Rust source file(s) discovered" }
  ]
}
```

Evidence is bounded and contains only relative paths and short labels — never
source text, environment values, or secrets. When a manifest or source signal is
missing, `confidence` is `weak`; when no recognized evidence exists at all, the
language and project type are `unknown`. The same selection is printed as
`Detection:` in terminal and Markdown reports and by `doctor`.

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

### Waivers with expiry

A suppression hides a finding indefinitely. A **waiver** is a time-limited,
owned suppression configured in `soroban-scan.toml`:

```toml
[[waivers]]
path = "src/legacy/**"
rule = "SS-001"
owner = "security-team"
reason = "migration tracked in SEC-42"
expires = "2026-12-31"
```

- `owner` and `reason` are required and must not be empty. A waiver without a
  stated reason is rejected as invalid configuration (exit code `2`).
- `expires` is the last day the waiver applies, as a UTC `YYYY-MM-DD` date.
- While unexpired, a waiver removes matching findings from the `--fail-on` gate
  exactly like a suppression, but they stay in the report with `source:
  "waiver"`, the owner, and the expiry date.
- After the expiry date the waiver stops applying. Matching findings return to
  the gate, a `CONFIG-003` **error** is emitted, and the scan exits `1` unless
  `--fail-on none` is given. Expired waivers are reported even when they match
  no finding, so stale risk acceptances cannot go unnoticed.
- Every configured waiver appears in JSON under `waivers` with `expired`,
  `matched`, `findings_suppressed`, and `applied`, including unused entries.

Waivers run after inline directives and configured suppressions, so an inline
directive or suppression wins if both apply. `config validate` rejects malformed
waivers before a scan runs.

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

### SARIF policy annotations

`--sarif-policy <LEVEL>` (requires `--format sarif`) adds the policy decision
to each SARIF result, inside the schema's `properties` bag:

```bash
soroban-scan scan ./contracts --format sarif --sarif-policy high \
  --output results.sarif
```

Each result gains `properties.policyStatus` (`fail`, `pass`, `accepted`, or
`suppressed`) and a short `properties.policyReason`:

```json
"properties": {
  "severity": "high",
  "policyStatus": "fail",
  "policyReason": "severity high meets the policy threshold high"
}
```

The annotations are opt-in: without the flag the SARIF output is unchanged.
They describe existing report state only (severity, baseline status, and
suppression) and add no source text, environment data, or secrets. Policy
annotations are bounded to the results already present in the report.

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

### Monorepo path filtering

Scanning a whole monorepo on every pull request is slow and noisy. Three opt-in
flags narrow a scan of one directory `PATH` (the repository root) to the Cargo
projects that matter:

```bash
git diff --name-only "origin/main...HEAD" > changed.txt
soroban-scan scan . --changed-files changed.txt \
  --exclude-project 'contracts/vault'
```

A **project** is any directory under `PATH` that contains a `Cargo.toml`,
including `PATH` itself (shown as `.`) and nested workspaces and members. The
filters apply in this order; the first that rejects a project wins:

1. `--exclude-project <GLOB>` (repeatable) skips a project whose root-relative
   directory matches, together with every project nested inside it.
2. `--include-project <GLOB>` (repeatable) keeps only projects that match, or
   that are nested in a project that matches, so including a workspace includes
   its members. Without it every project is included.
3. `--changed-files <FILE>` keeps only projects that own at least one listed
   file. A file belongs to the **deepest** project that contains it, so a change
   in `contracts/vault/src/lib.rs` selects `contracts/vault`, not `contracts`.
   A file outside every project selects nothing.

Globs use the same syntax as `--exclude` and match the project directory
relative to `PATH` (for example `contracts/token`); `*` may cross `/`. A
selected project nested in another selected project is scanned as part of it;
unselected projects nested in a scanned one are left out of that scan.
Reported paths stay relative to `PATH`. `--exclude` globs apply relative to
each scanned project.

The effective scope is printed to stderr before the report (`--quiet` hides
it). For the command above, when only `contracts/token/src/lib.rs` changed:

```text
effective scope: 1 of 6 project(s): contracts/token
  skipped . (unchanged)
  skipped contracts (unchanged)
  skipped contracts/vault (excluded)
  skipped contracts/vault/adapter (excluded)
  skipped tools/gen (unchanged)
```

When nothing is selected the scan reports no findings and exits `0`. Without
any of the three flags the scan is unchanged.

Safety and limits:

- The project walk never follows symbolic links, skips `target`, `.git`,
  `node_modules`, `vendor`, and the other always-ignored directories, and stops
  at depth 8 and 512 projects (with a warning).
- Changed-file entries must be relative to `PATH`; absolute paths and `..`
  components are usage errors (exit code `2`), so nothing outside the
  repository root is scanned. Lists are capped at 8 MiB and 20,000 entries;
  blank lines and `#` comments are ignored.
- Project globs may not start with `/` or contain `..`.
- `PATH` must be a single directory. `--changed-files` cannot be combined with
  `--files-from`, and none of the flags work with `--stdin-filename`.

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

### Report redaction

`--redact <FIELD>` replaces selected fields with a stable `sha256:` hash before
rendering. It is off by default, bounded to 32 distinct fields, and can also be
configured with `redact = [...]` in `soroban-scan.toml`:

```bash
soroban-scan scan ./contracts --format json \
  --redact finding.evidence \
  --redact finding.location.file \
  --redact suppression.reason \
  --output report.redacted.json
```

| Field | What is hashed |
| ----- | -------------- |
| `project.root` | The project root label. |
| `finding.title` | Finding titles, including suppressed findings and resolved baseline entries. |
| `finding.description` | Finding descriptions. |
| `finding.evidence` | Source evidence snippets. |
| `finding.remediation` | Remediation guidance. |
| `finding.location.file` | Finding file paths. |
| `suppression.reason` | Inline, configured, and waiver suppression reasons. |
| `suppression.file` | Inline suppression directive files and configured suppression globs. |
| `waiver.owner` | Waiver owner names. |
| `waiver.reason` | Waiver reasons. |
| `diagnostic.message` | Diagnostic messages. |
| `diagnostic.path` | Diagnostic file paths. |

- Redaction is presentation-only: it happens on a copy after the gate has been
  evaluated. `rule_id`, `location.line`, and especially `fingerprint` are never
  changed, so baselines, `compare`, and `dashboard` keep matching findings.
- The same value always hashes to the same `sha256:` value, which preserves
  correlation between a finding and its suppressed or baseline entry.
- **Limitation:** redaction only covers the fields above. It cannot detect
  sensitive text in arbitrary free-form content, and it does not rewrite rule
  metadata or any field not listed. Do not treat it as proof that a report is
  free of secrets. Keep source, environment values, and credentials out of
  reports entirely.

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

## `compare`

```text
soroban-scan compare BEFORE.json AFTER.json [--format terminal|json] [--output FILE]
```

Compares two JSON reports (`--format json`) and matches findings by the
documented [fingerprint](baselines.md#fingerprints): rule id, scan-relative
file, and normalized evidence. It prints `unchanged`, `new`, `fixed`, and
`renamed` counts, followed by the findings themselves:

```bash
soroban-scan scan ./contracts --format json --output old.json
soroban-scan scan ./contracts --format json --output new.json
soroban-scan compare old.json new.json
```

- A finding present in both reports with the same fingerprint is **unchanged**.
- An unmatched finding only in the newer report is **new**; only in the older
  report it is **fixed**.
- A finding that keeps its rule id and file but changes fingerprint (for
  example, because the flagged expression was edited) is **renamed**. Renamed
  pairs are listed with both fingerprints instead of being miscounted as a fix
  plus a regression. Rename pairing uses rule id and file only, so it is a
  best-effort explanation that should be reviewed.
- Reports are bounded to 64 MiB and 100,000 findings per file before parsing.
  Unsupported `schema_version` values and malformed documents are runtime errors
  (exit code `3`). Comparison never changes the reports or fails on findings.

## `dashboard`

```text
soroban-scan dashboard REPORT.json... [--title TEXT] [--output FILE]
```

Aggregates several JSON reports (oldest first) into one static,
self-contained HTML page:

```bash
soroban-scan dashboard scans/jan.json scans/feb.json scans/mar.json \
  --output trend.html
```

- Renders per-run files analyzed, total findings, and severity counts, plus a
  summary (latest findings and change from the first run) and an inline SVG
  bar chart.
- Uses inline CSS and SVG only: no JavaScript, remote fonts, stylesheets, or
  images, so the page renders offline.
- Never includes finding titles, evidence, or source text. Only counts and
  project labels are copied from the reports.
- Missing `stats` or `findings` data is shown as `—` and ignored when computing
  the latest value and change; an unknown severity drops the per-severity split
  but keeps the total.
- Bounded to 50 reports per dashboard, 16 MiB per report, and 100,000 findings
  per report. Oversized or malformed inputs are runtime errors (exit code `3`).

## `artifact-name`

```text
soroban-scan artifact-name --project NAME --commit SHA [--timestamp UTC] [--format FORMAT]
```

Prints the canonical artifact name for a report:

```text
<project>-<commit7>-<YYYYMMDDTHHMMSSZ>.<extension>
```

```bash
soroban-scan artifact-name --project "Vault Contract" \
  --commit "$(git rev-parse HEAD)" --format json
# vault-contract-abcdef1-20240301T102030Z.json
```

- `--project` is sanitized to lowercase `[a-z0-9._-]`; other characters become
  `-` and the label is capped at 64 characters. It can never contain a path
  separator or shell syntax.
- `--commit` accepts 7-64 hexadecimal characters; the first 7 are used.
- `--timestamp` is a UTC `YYYY-MM-DDTHH:MM:SSZ` value and defaults to the
  current time. Pass it explicitly when reproducing a name.
- `--format` selects the extension (`json`, `sarif`, `html`, `md`, `txt`, `xml`);
  it defaults to `json`.

The name is deterministic for the same inputs and contains no secrets. See
[Report retention and artifact naming](retention.md) for the scheme and the
recommended retention policy.

## `pack`

```text
soroban-scan pack [--dir DIR] install SOURCE
soroban-scan pack [--dir DIR] list
soroban-scan pack [--dir DIR] update SOURCE
soroban-scan pack [--dir DIR] uninstall NAME [--yes]
```

Manages locally installed community rule packs and records them in a
deterministic `registry.toml` lockfile (default `DIR`: `.soroban-scan/packs`).
Installs are offline, bounded, and never execute pack code. `uninstall` requires
interactive confirmation unless `--yes` is passed. See
[Rule pack CLI](rule-pack-cli.md).

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
  are visible, plus the effective `mode`, the opt-in `target` record, and the
  `detection` manifest. When `--max-findings` omits findings, a `truncation` object
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
  markup. It includes a deterministic `@media print` stylesheet (no external
  fonts or images) and a policy-status block with the `--fail-on` threshold and
  each finding's position relative to it, so the file renders and prints with
  the network disabled. Suitable for sharing with reviewers and audit packets.
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
