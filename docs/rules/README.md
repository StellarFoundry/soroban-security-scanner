# Security Rules

This document defines the rule system, severity/confidence semantics, and the
process for adding a new Soroban security detector.

## Rule identifiers

Rules use a stable identifier of the form:

```
SS-###   (Soroban Security)
```

Identifiers are **never reused** and **never renumbered**. A retired rule keeps
its identifier and is marked deprecated.

## Severity

Severity describes **potential impact if the issue is real**.

| Severity | Meaning |
| -------- | ------- |
| `critical` | Direct loss or theft of funds, or total loss of access control. |
| `high` | Serious security impact under plausible conditions. |
| `medium` | Security weakness that contributes to an exploit or degrades safety. |
| `low` | Minor weakness or hardening opportunity. |
| `info` | Informational; no direct security impact. |

## Confidence

Confidence describes **how certain the detector is that the finding is real**,
given the evidence it can observe statically.

| Confidence | Meaning |
| ---------- | ------- |
| `high` | Direct, unambiguous evidence in the source. |
| `medium` | Strong evidence, but assumptions or context required. |
| `low` | Heuristic; may be a false positive; requires human review. |

`severity` and `confidence` are independent. A high-severity issue detected only
heuristically is reported as `severity: high, confidence: low`, never
`confidence: high`.

## Categories

`authorization`, `authentication`, `access-control`, `cross-contract`,
`token`, `storage`, `arithmetic`, `error-handling`, `events`, `resource-usage`,
`configuration`, `dependencies`, `unsafe`.

## Built-in detectors

| Rule | Title | Severity | Confidence | Category |
| ---- | ----- | -------- | ---------- | -------- |
| [SS-001](detectors/SS-001.md) | State-changing entry point without caller authorization | high | medium | authorization |
| [SS-002](detectors/SS-002.md) | Cross-contract call without caller authorization | high | low | cross-contract |
| [SS-003](detectors/SS-003.md) | Unbounded storage iteration in an entry point | medium | low | resource-usage |
| [SS-004](detectors/SS-004.md) | Panic-prone construct in a contract entry point | low | medium | error-handling |
| [SS-005](detectors/SS-005.md) | Unsafe code in a Soroban contract | medium | high | unsafe |
| [SS-006](detectors/SS-006.md) | Persistent storage write without TTL management | low | low | storage |
| [SS-007](detectors/SS-007.md) | Hardcoded Stellar account or contract address | medium | low | configuration |
| [SS-008](detectors/SS-008.md) | Unchecked arithmetic in a contract entry point | medium | low | arithmetic |
| [SS-009](detectors/SS-009.md) | Insecure randomness derived from ledger state | medium | low | arithmetic |
| [SS-011](detectors/SS-011.md) | Initialization entry point without a re-initialization guard | high | low | access-control |
| [SS-013](detectors/SS-013.md) | Cross-contract call before state update | high | low | cross-contract |
| [SS-014](detectors/SS-014.md) | Token transfer amount without validation | medium | low | token |
| [SS-029](detectors/SS-029.md) | Public test or debug hook in a contract entry point | medium | medium | access-control |

Each detector has a positive and negative fixture under
`fixtures/corpus/<RULE-ID>/`.

## Registry introspection API

`RuleRegistry` exposes a small, read-only API so tooling (the `rules` command,
documentation generation, and metadata validation) does not reach into registry
internals:

| Method | Purpose |
| ------ | ------- |
| `metadata()` / `iter_metadata()` | Iterate every rule's metadata in registration order. |
| `metadata_sorted()` | Metadata sorted by rule id, the stable presentation order. |
| `metadata_by_category(category)` | Metadata for one category, sorted by id. |
| `by_category(category)` | Rules in one category, in registration order. |
| `by_id(id)` | Look up a single rule by id. |
| `len()` / `count()` | Number of registered rules. |
| `count_by_category(category)` | Number of rules in one category. |
| `category_counts()` | Deterministic `BTreeMap<Category, usize>` of per-category counts. |

The API is read-only by design; registration and mutation stay on
`register()`.

## Anatomy of a finding

- `rule_id`, `title`, `description`
- `severity`, `confidence`, `category`
- `file`, `line`, `column` (when available)
- `evidence` (a short, exact excerpt or structural fact)
- `remediation`
- `references`

## Adding a new rule

Before implementing a detector, answer all of the following:

1. **Problem** — what security problem does it address?
2. **Evidence** — what, exactly, is detectable statically?
3. **Limitations** — what can this detector *not* determine?
4. **False positives** — which legitimate patterns must not trigger it?
5. **Positive fixture** — a sample that must trigger.
6. **Negative fixture** — a sample that must not trigger.

Then:

7. Implement the detector against the rule interface.
8. Add unit tests and regression fixtures.
9. Document the rule and its remediation.
10. Set honest `severity` and `confidence`.

Rules must never fabricate evidence or source locations. When evidence is
insufficient, prefer `confidence: low` or do not report at all.

See [`../contributors/writing-rules.md`](../contributors/writing-rules.md) for a
step-by-step guide, [`cookbook.md`](cookbook.md) for three annotated end-to-end
examples, [`TEMPLATE.md`](TEMPLATE.md) for the rule document template,
[`../development/testing.md`](../development/testing.md) for the fixture
layout, and [`../../CONTRIBUTING.md`](../../CONTRIBUTING.md) for the definition
of done.

For the limits of the analysis and the meaning of confidence, see
[Analysis Methodology](../analysis-methodology.md).

## Rule documentation template

```markdown
### SS-XXX — <Title>

- **Severity:** <severity>
- **Confidence:** <confidence>
- **Category:** <category>

**Problem.** ...

**How it is detected.** ...

**Limitations.** ...

**False positives.** ...

**Remediation.** ...

**References.** ...
```
