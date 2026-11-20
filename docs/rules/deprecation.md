# Rule deprecation

Rule identifiers are part of the public contract. A rule may stop running, but
its identifier is **never deleted or reused**: baselines, configuration files,
and downstream consumers keep resolving the id while the rule is retired.

## Lifecycle

1. **Active** — the rule runs by default and is documented in
   [`docs/rules/README.md`](README.md).
2. **Deprecated** — the rule metadata is marked `deprecated = true`. The id
   stays resolvable, the detector is skipped by default, and configuration or
   baseline references produce a warning.
3. **Removed** — only after the minimum deprecation window. The id is retained
   as a tombstone in the documentation and may never be assigned to a new rule.

## Minimum deprecation window

A deprecated rule stays resolvable for **at least two minor releases** and
**at least 90 days**, whichever is longer. The clock starts when the release
that marks the rule deprecated is published. Removing a rule earlier requires a
maintainer decision recorded in the changelog.

## Marking a rule deprecated

Set the flag on the rule metadata and keep the id and detector code in place:

```rust
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-042",
    // ...
    deprecated: true,
};
```

The default implementation of `Rule::enabled_by_default` returns `false` for a
deprecated rule, so the engine skips it and counts it in `rules_skipped`.

## What users see

- The rule still appears in `soroban-scan rules` and `soroban-scan explain`,
  marked as deprecated, so the id remains discoverable.
- A configuration that lists the id in `rules.disabled`, `rules.enabled`,
  `rules.severity_overrides`, or `rules.confidence_overrides` emits
  `CONFIG-005`.
- A baseline that contains findings for the id emits `BASELINE-002`. Refresh the
  baseline to drop stale entries.

Both diagnostics are warnings. They never fail the gate, because a deprecated
rule is an expected, non-security event.

## Why not delete the rule

Deleting an id would make an existing baseline silently invalid and could let a
new rule inherit old suppressions. Keeping the id resolvable preserves the
audit trail and makes retirement reviewable.
