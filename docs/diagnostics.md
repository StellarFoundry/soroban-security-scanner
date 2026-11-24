# Diagnostics

Diagnostics are **not** security findings. They report something the scanner
could not do — a file it skipped, a manifest it could not read, a rule whose
output was rejected — so a scan can keep going and still tell you what was
missed. Findings are what fail the gate; diagnostics never do.

Every diagnostic carries a **stable code** and an explicit **level**, so tooling
can classify or suppress them without parsing the human-readable message.

## Fields

| Field | Description |
| ----- | ----------- |
| `code` | Stable identifier, for example `PARSE-001`. Never reused for a different meaning. |
| `level` | One of `info`, `warning`, `error`. |
| `message` | Human-readable description. May change between releases. |
| `path` | Related file, when there is one. |
| `line` | Related line, when there is one. |

## Codes

| Code | Level | Meaning |
| ---- | ----- | ------- |
| `PARSE-001` | warning | A source file could not be parsed; it was analyzed only as raw text. |
| `MANIFEST-001` | warning | A `Cargo.toml` could not be read or parsed; it was skipped. |
| `SOURCE-001` | warning | A source file exceeded the size limit and was skipped. |
| `SOURCE-002` | warning | A source file could not be read and was skipped. |
| `SOURCE-003` | warning | A `#[path = "..."]` module declaration escaped the crate root and was ignored. |
| `CRATE-001` | warning | A source file's crate root could not be determined unambiguously; the nearest workspace member or scan root was used. |
| `RULE-001` | error | A rule produced a location that is not a safe relative path; the finding was rejected. |
| `RULE-002` | error | A rule reported a file outside the analyzed set; the finding was rejected. |
| `RULE-003` | error | A rule produced a finding without evidence; the finding was rejected. |
| `RULE-004` | error | A rule panicked; the panic was isolated and its findings were discarded. |
| `RULE-005` | warning | A rule exceeded its configured time budget; its findings were discarded. |
| `CONFIG-001` | warning | A severity or confidence override has no effect because its rule is unknown or disabled. |
| `CONFIG-002` | warning | A configured suppression is invalid and was not applied. |
| `CONFIG-003` | error | A configured waiver has expired; it no longer suppresses findings and the run fails unless `--fail-on none` is set. |
| `CONFIG-004` | error | A configured waiver is invalid (missing owner, reason, or valid expiry) and was not applied. |
| `CONFIG-005` | warning | An active severity profile override has no effect because its rule is unknown or disabled. |
| `BASELINE-001` | warning | A baseline references a rule id that is no longer registered; the entry remains forward compatible. |
| `AI-001` | warning | The optional assistance layer reached its configured request budget; the scan continued without further AI calls. |
| `AI-002` | warning | Repeated provider failures opened the assistance circuit breaker; the scan continued without further AI calls. |
| `MODE-001` | info | Generic mode is active; Soroban-only rules were skipped. The diagnostic names the project classification and how many rules were disabled. |
| `TARGET-001` | warning | Target analysis is enabled for an explicit target other than wasm32. Only wasm32 is analyzed; the scanner did not build the project. |
| `TARGET-002` | info | A wasm32 target was detected; target-specific dependencies were filtered. The scanner did not build or execute the project. |
| `TARGET-003` | warning | A Cargo target configuration file could not be read or parsed and was ignored. |
| `SYNTAX-001` | warning | Source files in a language the Rust frontend cannot analyze were skipped. Emitted only with `--unsupported-syntax`, aggregated by language, and bounded to 8 kinds plus an omitted-count notice. Only file extensions are inspected; no source text is read or reported. |
| `TYPE-001` | warning | A type name used by an entry point could not be resolved unambiguously. Emitted for parameter types, local type annotations, and cast targets, aggregated by construct and type name with the first span. Type-aware rules may not apply. Bounded to 8 diagnostics per scan plus an omitted-count notice. |
| `SDK-001` | warning | The declared `soroban-sdk` version is outside the supported matrix (`>=20.5.0, <30.0.0`). The scan continues, but rule coverage may be inaccurate. The message lists the verified versions. |
| `CFG-001` | warning | A function's control-flow graph hit a node, edge, or depth cap and was truncated. Rules that require a complete graph skip that function instead of making a partial claim. Bounded to 8 diagnostics per scan plus an omitted-count notice. |
| `CFG-002` | warning | A construct the control-flow model does not support (an item, macro, `break`, `continue`, closure, `async` block, or unresolved bare-`loop` exit) is present. Aggregated per kind across the scan with counts, bounded to 8 kinds plus an omitted-count notice, and emitted with no path, line, or source text. Rules that need complete reachability may be less precise near such a construct. |
| `TAINT-001` | warning | A taint flow may be missing or incomplete because a helper was undefined, a construct is outside the taint model, or an analysis bound was reached. Aggregated by reason and sink with the first span, and bounded to 8 diagnostics per scan plus an omitted-count notice. Messages contain counts and fixed labels only, never source text. |
| `SCAN-001` | warning | The overall scan deadline expired. Remaining rules were skipped and the report is **partial**; do not treat it as a complete result. |

Codes are grouped by area: `PARSE-*`, `MANIFEST-*`, `SOURCE-*`, `CRATE-*`,
`RULE-*`, `CONFIG-*`, `BASELINE-*`, `MODE-*`, `TARGET-*`, `SYNTAX-*`,
`TYPE-*`, `SDK-*`, `CFG-*`, and `TAINT-*`. `config validate` prints `CONFIG-*`
warnings to stderr while still exiting successfully, because they do not prevent
a scan from running.

## JSON output

Diagnostics appear under `diagnostics` in `--format json`:

```json
{
  "code": "PARSE-001",
  "level": "warning",
  "message": "failed to parse source: expected an expression, found `{`",
  "path": "src/lib.rs"
}
```

The terminal report prints each diagnostic with its code (`- [PARSE-001] ...`),
and `--verbose` echoes them to stderr with the same prefix.

## Stability

Once a code is released it keeps its meaning. New codes may be added; existing
codes are not renamed or repurposed. Treat the code and level as the stable
interface and the message as informational.
