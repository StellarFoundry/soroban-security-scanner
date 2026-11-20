# Editor integration specification (LSP spike)

Status: **spike / proposal** · Issue: #168

This document evaluates editor integration options, recommends the smallest
useful design, and lists the follow-up work needed to ship it. It is a design
record, not an implementation. The goal is in-editor findings without executing
scanned code, without duplicating the rule engine, and without turning the
scanner into a long-running security service by accident.

## Problem

Today a developer must leave the editor, run `soroban-scan scan`, and read a
terminal, Markdown, or SARIF report. That is acceptable for CI but slow for the
tight edit/scan loop. We want findings next to the code as diagnostics, while
keeping the deterministic CLI as the source of truth.

## Goals

- Show findings for the file or workspace being edited, with rule id, severity,
  confidence, message, and an exact source range.
- Reuse `soroban-scan-core` for discovery, parsing, rule evaluation, and
  suppression semantics. No second rule implementation.
- Start instantly, scan incrementally, and never block the editor indefinitely.
- Work offline and never execute, build, deploy, or mutate scanned code.
- Let users jump from a diagnostic to the rule documentation and remediation.
- Keep the CLI/JSON/SARIF contract unchanged.

## Non-goals (for the first milestone)

- Code actions or autofixes.
- Completion, formatting, rename, or refactoring.
- A hosted service, telemetry, or multi-user state.
- Background scanning of unrelated repositories.
- Replacing CI gating or the `--fail-on` policy.
- AI assistance inside the editor in the first milestone.

## Options considered

### A. Full language server (recommended long-term shape)

A `soroban-scan lsp` subcommand speaking LSP over stdio, with diagnostics for
open/saved documents. Editors with LSP support (VS Code, Neovim, Helix, Emacs,
Zed, JetBrains via plugins) get integration from one implementation.

Pros: standard protocol, reusable across editors, supports future code actions
and hover. Cons: more protocol surface, lifecycle/cancellation complexity, and a
temptation to grow into a full language server before the diagnostics path is
proven.

### B. Diagnostics-file only

The CLI writes JSON/SARIF and a thin editor extension watches the file or runs
the CLI on save.

Pros: tiny, no new server, reuses existing formats. Cons: no standard way to
publish diagnostics, each editor needs custom glue, file watching and process
management are editor-specific, and stale results are hard to reason about.

### C. Minimal diagnostics provider (recommended first milestone)

A deliberately small subset of LSP:

- `initialize` / `initialized` / `shutdown` / `exit`;
- `textDocument/didOpen`, `didChange` (debounced), `didSave`, `didClose`;
- `textDocument/publishDiagnostics`;
- optional `workspace/didChangeConfiguration` later.

Hover on rule IDs is served by `soroban_scan_core::hover` (severity,
confidence, and short remediation from built-in metadata; offline and bounded;
unknown IDs get a generic fallback). No code actions, completion, or custom
requests in v1. This keeps the
protocol surface small enough to test with JSON-RPC fixtures, while giving every
LSP-capable editor useful diagnostics immediately. It can grow into option A
without changing the editor side.

**Recommendation: C first, with the process and message types shaped so A is an
additive evolution.**

## Architecture

```text
editor
  │  LSP over stdio (JSON-RPC 2.0, Content-Length framing)
  ▼
soroban-scan lsp
  │
  ├── workspace/config loader   (reuses config::ScanConfig)
  ├── document store            (in-memory text + version)
  ├── scan scheduler            (debounce, cancel, one scan at a time)
  ├── core analysis             (project::load_files_with_options + engine::scan)
  └── diagnostics mapper        (Finding -> LSP Diagnostic)
        │
        └── soroban-scan-core (library; no editor knowledge)
```

The server is a thin adapter. All analysis stays in the core library so CLI and
editor results cannot drift.

## Reuse of the core library

| Need | Existing API |
| ---- | ------------ |
| Load config and discovery options | `config::ScanConfig`, `discovery::DiscoveryOptions` |
| Parse a document or project | `project::load_files_with_options`, `source::parse_source_with_options` |
| Run rules and apply suppressions/baselines | `engine::scan`, `engine::scan_source_str` |
| Finding fields and ranges | `finding::Finding`, `finding::SourceLocation` |
| Rule metadata for messages | `registry::RuleRegistry` |
| Render a rule link/details | `report::render_rule_detail` (optional) |

The first milestone may scan only the changed document with
`engine::scan_source_str`, but that can disagree with a project scan for rules
that need project context. The preferred default is a debounced project scan
using `project::load_files_with_options` restricted to the workspace file set,
falling back to a single-file scan when the project is too large or cannot be
loaded. The chosen mode must be visible in the diagnostic source and documented;
it must never silently present weaker results as a full project scan.

## Protocol scope (v1)

### Lifecycle

- `initialize`: advertise `textDocumentSync = Incremental` (or `Full` if
  incremental mapping is not ready), `diagnosticProvider` is **not** used in v1;
  publish diagnostics instead.
- `initialized`: load configuration and index the workspace lazily.
- `shutdown` / `exit`: stop the scheduler, drop document text, exit cleanly.

### Document events

- `didOpen`: store text/version, schedule a scan.
- `didChange`: apply full or incremental changes, bump version, debounce
  (recommended 300–500 ms).
- `didSave`: schedule an immediate scan (save is an explicit intent signal).
- `didClose`: clear in-memory text and publish an empty diagnostic list for that
  URI.

### Diagnostics

Publish `textDocument/publishDiagnostics` with:

| LSP field | Source |
| --------- | ------ |
| `range` | `Finding.location` line/column/end positions, converted from the scanner’s 1-based line/column to LSP’s 0-based positions |
| `severity` | `critical`/`high` → `Error`, `medium` → `Warning`, `low`/`info` → `Information` (document the mapping) |
| `code` | `rule_id` (for example `SS-001`) |
| `codeDescription.href` | rule documentation URL, when available |
| `source` | `soroban-scan` |
| `message` | title, evidence, remediation, and confidence; never fabricated text |
| `data` | optional `{rule_id, severity, confidence, category, fingerprint}` for future code actions |

Suppressed findings are not published as editor diagnostics by default (they are
excluded from the gate), but the server may expose them behind a setting later.

## Configuration and workspace handling

- Resolve the workspace root from `initialize.rootUri` and the nearest
  `Cargo.toml`/`soroban-scan.toml`.
- Reuse the same layered config as the CLI, including excludes and
  `exclude_tests`. Repository config is untrusted and cannot enable network
  access, execution, or AI.
- Respect `files.exclude`/editor ignore rules only where they match the CLI’s
  discovery semantics; do not silently scan vendored or generated trees.
- Bound the workspace: maximum file count, maximum file size, and a hard scan
  deadline. On timeout, publish a single informational diagnostic and keep the
  previous results rather than claiming a clean scan.
- Debounce, coalesce, and cancel superseded scans. At most one scan runs at a
  time; a newer edit cancels the older request.

## Security and privacy

- Never compile, execute, deploy, sign, or mutate scanned code.
- Never make network requests in the LSP path. AI assistance is out of scope for
  v1 and must remain opt-in if added later.
- Never write to the workspace except an explicit user-invoked command.
- Treat document text, paths, and configuration as untrusted input. Do not
  interpolate them into shell commands or log them verbatim.
- Keep diagnostics local to the editor; no telemetry.
- Apply the same path-confinement and diagnostics-safety checks as the CLI
  (`RULE-001`/`RULE-002`/`RULE-003`).
- A malformed JSON-RPC frame, oversized message, or missing `Content-Length`
  must fail closed (error response or clean shutdown), not panic.

## Performance targets

- `initialize` responds in < 100 ms for a typical workspace.
- An edit-to-diagnostic loop completes in < 500 ms for a single file on a
  developer laptop, excluding very large projects.
- Memory stays proportional to open documents plus the project file index, not
  to total repository size.
- No unbounded queues: debounce, coalesce, and cancel.

## Testing plan

- Unit tests for JSON-RPC framing (headers, content length, partial reads,
  malformed input, oversized message).
- Unit tests for document store/version handling and range conversion.
- Diagnostics mapper tests for each severity, multi-line ranges, no-column
  findings, and suppression behavior.
- Integration test that starts the server over stdio, opens a fixture, and
  asserts diagnostics for a known finding.
- A “no execution” test that scans a fixture containing a `build.rs`/proc macro
  and proves nothing is invoked.
- Manual smoke tests in VS Code and Neovim.
- Keep the existing CLI/JSON/SARIF golden tests unchanged.

## Delivery plan and follow-up issues

These should be filed as separate issues after this spike is reviewed:

1. **`feat(cli): add soroban-scan lsp JSON-RPC transport`** — framing, lifecycle,
   graceful shutdown, bounded messages, tests.
2. **`feat(lsp): publish file diagnostics from the core engine`** — document
   store, debounce/cancel, range/severity mapping, fixture integration test.
3. **`feat(lsp): project-aware scans and configuration`** — workspace root,
   excludes, project scan mode, timeout/bounds, config reload.
4. **`feat(editor): ship a minimal VS Code client`** — thin LSP client, grammar
   for `soroban-scan.toml`, setup docs.
5. **`docs(editor): Neovim, Helix, and Emacs setup recipes`** — tested configs.
6. **`feat(lsp): code actions for rule docs and baseline suppression`** — only
   after diagnostics are stable.

## Risks

- **Project-context drift:** single-file scans can differ from project scans.
  Mitigate by preferring project scans and labeling the mode.
- **Editor-specific LSP quirks:** test at least two clients before declaring the
  protocol stable.
- **Dependency growth:** a full LSP framework may be unnecessary for v1. Start
  with the existing `serde_json` dependency and a small framing layer; adopt a
  crate only if the protocol work justifies it under ADR-0005.
- **Long scans:** enforce deadlines and publish stale-result notices rather than
  hanging the editor.

## Decision requested

Approve the minimal-diagnostics-provider approach (option C), the v1 protocol
scope, and the follow-up issue list above. Implementation should not begin until
the core library API needed by the server is confirmed stable.
