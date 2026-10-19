# Observatory integration contract

This page defines how `soroban-scan` integrates with downstream consumers —
most importantly the **Stellar Contract Observatory** — as the project's
**security-analysis subsystem**.

The integration is by **stable, versioned machine-readable output**, not by
sharing code. The scanner analyzes contracts and emits findings; the Observatory
consumes them alongside its own contract-inventory, specification, interface and
verification capabilities. This keeps the two projects loosely coupled, lets each
evolve independently, and avoids any hidden coupling or duplicated logic.

## Contract at a glance

```
Observatory (contract intelligence)          soroban-scan (security subsystem)
  discover contracts  ─┐
  inventory / spec     │
  interface / diff     │        ┌───────────────────────────────────────┐
  verify / deploy      │  scan  │  JSON report  (schema_version = 1)     │
  ───────────────────► └───────►│  SARIF 2.1.0  (code scanning)          │
                               └───────────────────────────────────────┘
                                        findings + diagnostics + stats
```

The scanner never executes, deploys, signs, or mutates the code it analyzes, and
makes no network requests. See [Security Model](../security/security-model.md).

## Producing the report

```bash
soroban-scan scan <path> --format json --output report.json --fail-on none
soroban-scan scan <path> --format sarif --output results.sarif
```

- JSON is the primary integration format.
- SARIF 2.1.0 is for GitHub code scanning and compatible tools.

## Stability promise

- The JSON report carries an explicit integer **`schema_version`** (currently
  `1`), independent of the tool version.
- Within a `schema_version`, changes are **additive and backward compatible**:
  new fields may appear; existing fields keep their meaning.
- A change that removes or renames a field, or changes a field's type or meaning,
  increments `schema_version` and is documented in `CHANGELOG.md`.
- Field names are `snake_case`. Enum values are stable strings:
  - `severity`: `info` | `low` | `medium` | `high` | `critical`
  - `confidence`: `low` | `medium` | `high`
  - `category`: `authorization` | `authentication` | `access-control` |
    `cross-contract` | `token` | `storage` | `arithmetic` | `error-handling` |
    `events` | `resource-usage` | `configuration` | `dependencies` | `unsafe`
- Source paths use **forward slashes** on every OS for reproducible output.
- Output is **deterministic**: identical input yields byte-identical findings.

## Finding order

`findings` is ordered by the stable key
`(file, line, column, rule_id, fingerprint)`, comparing files and rule ids as
strings and treating a missing column as `0`. This ordering is part of the
contract: consumers and snapshot tests may rely on it, and every output format
(terminal, JSON, SARIF, Markdown) preserves it. Ties at the file/line level are
broken by column, then rule id, then fingerprint.

## Effective configuration

`effective_config` records the settings that produced the report (after config
file discovery and command-line overrides), making CI results reproducible:
minimum severity/confidence, exclude globs, symlink handling, disabled/enabled
rules, per-rule severity/confidence overrides, and the optional AI settings.
It is the serializable scan configuration; environment variables, credentials,
and absolute user paths are never included.

A machine-readable [JSON Schema](report.schema.json) accompanies this document.

When a report is bounded with `--max-findings`, an optional top-level
`truncation` object records `shown`, `total`, and `omitted`. The failure gate is
always evaluated before truncation, so consumers can trust the exit code even
when `findings` is shorter than `truncation.total`.

## Top-level shape

```jsonc
{
  "schema_version": "1",
  "tool":    { "name": "soroban-scan", "version": "…", "information_uri": "…" },
  "project": {
    "root": "…",
    "kind": "generic_rust | likely_soroban | confirmed_soroban",
    "source_files": 0,
    "soroban_sdk_versions": ["…"]
  },
  "stats": {
    "files_analyzed": 0,
    "rules_run": 0,
    "rules_skipped": 0,
    "findings_raw": 0,
    "findings_rejected": 0,
    "suppressions_detected": 0,
    "findings_suppressed": 0
  },
  "effective_config": {
    "min_severity": "info",
    "min_confidence": "low",
    "exclude": [],
    "follow_symlinks": false,
    "rules": {
      "disabled": [],
      "enabled": [],
      "severity_overrides": {},
      "confidence_overrides": {}
    },
    "ai": { "enabled": false, "provider": null, "model": null }
  },
  "findings": [ /* see below */ ],
  "suppressed": [ /* finding + the inline directive that suppressed it */ ],
  "suppressions": [ /* every detected directive, used or not */ ],
  "diagnostics": [
    { "level": "warning", "message": "…", "path": "…", "line": 0 }
  ]
}
```

## Finding shape

```jsonc
{
  "rule_id": "SS-008",
  "title": "Unchecked arithmetic in a contract entry point",
  "description": "…",
  "severity": "medium",
  "confidence": "low",
  "category": "arithmetic",
  "location": { "file": "src/lib.rs", "line": 23, "column": 9 },
  "evidence": "unchecked `-` arithmetic in entry point `withdraw`: balance - amount",
  "remediation": "…",
  "references": ["https://…"],
  "fingerprint": "…"
}
```

- **`fingerprint`** is a stable hash of `rule_id` + file + normalized evidence.
  The line number is **excluded**, so a finding keeps its identity across
  unrelated line shifts — this is what baselines and "new findings only" rely on.
  See [Baselines](../baselines.md).
- **`evidence`** always cites concrete source text. The scanner never fabricates
  findings, locations, or evidence.
- **`confidence`** is independent of `severity`. Heuristic detectors report low
  confidence rather than overstating certainty.

## Inline suppressions

In-source directives (`// soroban-scan: ignore SS-XXX -- reason`) remove a
finding from the **gate**, never from the **report**:

- `findings` contains only the findings that reach the gate.
- `suppressed` contains each suppressed finding (same shape as a finding) plus
  a `suppression` object with `file`, `line`, `rules` and the optional `reason`.
- `suppressions` lists every detected directive, including directives that
  matched nothing (`applied: false`), so suppression usage is auditable.
- `stats.findings_suppressed` and `stats.suppressions_detected` carry the
  counts.

SARIF keeps suppressed findings in `results` and marks them with the SARIF
2.1.0 in-source suppression object:

```jsonc
"suppressions": [ { "kind": "inSource", "status": "accepted", "justification": "..." } ]
```

See [Inline suppressions](../suppressions.md).

## What the Observatory consumes

1. Contract/project inventory and identity come from the Observatory's own
   discovery and specification crates.
2. `soroban-scan` contributes the `findings` array for those contracts (matched
   by file path and rule id), plus `stats` and `diagnostics`.
3. A consumer can produce a project-level view:

   ```
   PROJECT → CONTRACTS → ENTRY POINTS → ANALYSIS → FINDINGS → RISK SUMMARY
   ```

Because the interface is versioned and additive, the Observatory can upgrade the
scanner without a coordinated release, and vice versa.

## Versioning

| Report `schema_version` | Tool | Notes |
| ----------------------- | ---- | ----- |
| `1` | `>= 0.2.0` | First published integration contract (JSON report + SARIF). |

- `schema_version` `1` gained `stats.suppressions_detected`,
  `stats.findings_suppressed`, and the `suppressed` and `suppressions` arrays
  (additive, inline suppressions).

When the contract changes, update this table and
[`report.schema.json`](report.schema.json) together.
