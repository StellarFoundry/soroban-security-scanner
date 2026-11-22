# Finding ranking

Findings are ranked so that the most actionable ones appear first. Ranking
changes only the order of the report; it never filters, hides, merges, or
re-labels a finding. Every finding that passes the configured severity and
confidence thresholds is still present.

## Ranking key

The stable key, implemented by `Finding::sort_key` in
`crates/soroban-scan-core/src/finding.rs`, is:

```
(severity, confidence, reachability, file, line, column, rule_id, fingerprint)
```

The first three components are compared **highest first**:

1. **Severity**: `critical`, `high`, `medium`, `low`, `info`.
2. **Confidence**: `high`, `medium`, `low`.
3. **Reachability**: `reachable`, `unknown`, `unreachable`.

The remaining components are the deterministic span order used by earlier
releases: normalized file path (forward slashes), line, column (missing column
is `0`), rule id, then fingerprint. Those tie-breakers make the order total and
stable, so identical input produces byte-identical output.

Severity and confidence overrides from configuration are applied before
ranking, so the key reflects the effective values in the report.

## Reachability

Reachability comes from the per-function [control-flow graph](control-flow.md)
and is recorded per finding line:

- `reachable` — the line is covered by a reachable CFG node.
- `unreachable` — the line is covered only by nodes the graph cannot reach.
- `unknown` — the file did not parse, no function contains the line, or the
  construct is not modelled.

Unknown ranks between reachable and unreachable: a finding is treated as
actionable until the analysis can prove otherwise. The annotation is internal
and is not serialized into JSON or SARIF; reports loaded from disk rank as
`unknown`.

## Stability and formats

The scanner sorts after configuration overrides, validation, and
de-duplication. `merge` re-sorts merged outcomes with the same key. Terminal,
JSON, SARIF, Markdown, and HTML renderers preserve the outcome's order.

The order is pinned by
`crates/soroban-scan-core/tests/ordering_contract.rs` and by the report
snapshots under `crates/soroban-scan-core/tests/snapshots/`. Any intentional
ordering change must update those deliberately:

```text
UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test report_snapshots
```
