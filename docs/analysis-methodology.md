# Analysis Methodology

`soroban-scan` is a static analyzer. This document explains what that means in
practice: what the scanner can prove, what it cannot prove, and how it decides
how much confidence to place in a finding.

> **The scanner is not an audit replacement.** A clean scan means the detectors
> found no matching evidence in the analyzed files. It does not mean the
> contract is secure, correct, or free of exploitable bugs. Use the scanner
> alongside threat modeling, tests, and professional review.

## What the scanner does

The pipeline is deliberately small and deterministic:

1. **Discover** Rust source files and manifests under the scan root.
2. **Classify** the project as a Soroban contract, a likely Soroban project, or
   generic Rust. Most detectors only run for confirmed Soroban projects.
3. **Parse** each file with `syn`. Parse failures are diagnostics, not crashes.
4. **Extract facts** from the syntax tree: function signatures, method calls,
   macros, string literals, arithmetic operators, `unsafe` blocks, and
   `require_auth` calls.
5. **Summarize helpers.** Same-file helper functions are followed up to a small
   depth so a `require_auth` or TTL call in a helper can satisfy a check.
6. **Run detectors.** Each detector appends findings with evidence and a source
   location.
7. **Validate and filter.** Findings outside the analyzed file set, findings
   without evidence, and findings below the configured thresholds are removed.
8. **Apply policy.** Rule and category filters, severity and confidence
   overrides, baselines, and inline suppressions are applied in that order where
   relevant.

The scanner never compiles, executes, deploys, signs, or mutates the code it
analyzes. It makes no network requests.

Embedders may observe the pipeline through optional `engine::PipelineHooks`.
Hooks are called synchronously between stages with a read-only `StageSummary`
containing only the stage name and counts. They cannot alter findings or
configuration, receive no source text, and get no network or code-execution
capability. With no hooks registered, behavior is identical to a plain scan.

## What static analysis can establish

Static analysis can establish facts about the source text with high precision:

- A public function exists in a `#[contractimpl]` block.
- A call such as `env.storage().persistent().set(...)` appears in a function.
- A function contains no `require_auth` call and no same-file helper that does.
- A string literal matches the shape of a Stellar account or contract address.
- A value is written to persistent storage without a TTL call in the same
  analyzed scope.

These are **presence and absence facts about syntax**, not statements about
runtime behavior. They are reproducible: the same source and configuration
produce the same findings in the same order.

### Type environment

Rules can query an immutable type environment exposed by the analysis context.
It records type names that are written in the source for items, function
parameters, and typed locals, keyed by the declared item and its span. Lookups
respect lexical shadowing and return `unknown` for a missing item, an
out-of-scope span, or a declaration without a written type. The environment does
not infer types, so `unknown` means "not visible here", never a guessed type.

## What static analysis cannot establish

The scanner cannot generally prove:

- **Exploitability.** A missing authorization check is a risk only if an
  attacker can reach the function and the state change matters. The scanner
  does not model attackers or economic incentives.
- **Reachability across files or contracts.** Helper summaries stop at file
  boundaries and at a bounded depth. Authorization or TTL management in another
  module, contract, or deployment script is invisible.
- **Runtime values.** Addresses, balances, flags, and storage keys are not
  evaluated. A constant that looks dangerous may be unreachable; a dynamic value
  that is dangerous may look harmless.
- **Macro-generated code.** Code produced by procedural macros is not expanded
  by the parser. A detector sees the macro invocation, not what it expands to.
- **Absence of all vulnerabilities.** The rule set is finite and intentionally
  conservative. No finding is not a proof of safety.
- **Business-logic correctness.** The scanner has no specification of what the
  contract is supposed to do.

When a question requires runtime behavior, external state, or cross-contract
reasoning, the honest answer is "needs human review", not a stronger finding.

## How confidence is assigned

Severity and confidence answer different questions:

- **Severity** is the potential impact if the finding is real.
- **Confidence** is how certain the detector is that the reported pattern is
  genuinely present and relevant, given the evidence it can observe.

| Confidence | Meaning | Typical evidence |
| ---------- | ------- | ---------------- |
| `high` | Direct, unambiguous evidence in the analyzed source | A literal `unsafe` block, or a direct syntactic construct with no plausible benign reading |
| `medium` | Strong evidence, but context or an assumption is required | A public state-changing entry point with no authorization anywhere in the analyzed scope |
| `low` | Heuristic; may be a false positive; requires human review | A persistent write whose TTL may be managed elsewhere |

Confidence is not a function of severity. A high-impact issue detected only by a
heuristic is reported as `severity: high, confidence: low`, never as
`confidence: high`. This is intentional: overstating confidence is a security
problem of its own because it encourages users to skip review.

## Worked examples

### SS-001: structural evidence with a context gap

[SS-001](rules/detectors/SS-001.md) reports a public entry point that mutates
storage and has no `require_auth` or `require_auth_for_args` in its body or in
same-file helpers.

The detector can prove:

- the function is public and inside a contract implementation;
- it performs a storage mutation;
- the analyzed function and its same-file helper closure contain no
  authorization call.

It cannot prove:

- that no authorization happens in a callee in another file or contract;
- that the function is intentionally permissionless;
- that an attacker can actually reach the state change.

That gap is why the default confidence is `medium` rather than `high`. The
positive fixture is
[`fixtures/corpus/SS-001/positive.rs`](../fixtures/corpus/SS-001/positive.rs);
the negative fixture shows both direct and helper-based authorization.

### SS-006: heuristic evidence with a policy gap

[SS-006](rules/detectors/SS-006.md) reports a persistent-storage write with no
TTL management in the same function or same-file helper closure.

The detector can prove:

- the write targets persistent storage;
- no `extend_ttl`, `set_ttl`, or `bump` call appears in the analyzed scope.

It cannot prove:

- that TTL is not extended by a maintenance entry point or another module;
- that the stored value must survive long enough to need extension;
- that the contract's TTL policy is wrong.

That gap is why the default confidence is `low`. The positive and negative
fixtures are under
[`fixtures/corpus/SS-006/`](../fixtures/corpus/SS-006/). The rule is still
useful because the pattern is cheap to check and the consequences of expired
persistent data can be severe.

## Cast type tracking

`rules::util::cast_facts` records every `expr as Type` in an entry point and
reduces both sides to an `IntegerType` (signedness and bit width) when the
source makes them visible: a parameter type, a local annotation, an integer
literal suffix, or a storage `get::<_, T>` turbofish. `CastFact::integer_cast`
returns `None` when either side is not a visible integer, and the cast is never
guessed. `IntegerCast::is_lossy` marks truncating casts and signedness changes;
`i32 as u64`, for example, is lossy because negative values do not round-trip.
Fixtures for widening, narrowing, and signed/unsigned casts live under
[`fixtures/casts/`](../fixtures/casts/). SS-018 continues to report only
narrowing casts of parameters and storage reads, so the API is additive.

## Map storage keys

`analysis::storage::map_storage_accesses` resolves the key and value types of a
stored `Map` from a storage turbofish (`get::<_, Map<K, V>>`) or a typed local
initialized from storage. Keys are classified as `Symbol`, `Address`, a tuple of
those, or `Unknown`. An unrecognized or generic key type is `Unknown`; it is
never assumed bounded. SS-016 uses the resolved key type to state when a stored
map's key type could not be determined. Fixtures are under
[`fixtures/storage-maps/`](../fixtures/storage-maps/).

## Manifest inheritance and module paths

Workspace members often use `soroban-sdk = { workspace = true }`. The scanner
reads `[workspace.dependencies]` from the nearest ancestor workspace root and
fills in the inherited version, merged features, and default-feature setting
while keeping `source = workspace` to record that the value was inherited
rather than declared on the member. This makes inherited SDK versions visible to
SS-015 and `soroban.sdk_versions`.

Module paths follow external `mod name;` declarations from each crate root:
`foo.rs` and `foo/mod.rs` are resolved per the Rust reference, and
`#[path = "..."]` is honored. A `#[path]` target that escapes the crate root is
rejected with `SOURCE-003`; the file keeps its best-effort file-based path.
Unreachable files also keep the file-based fallback.

## Rule isolation

Every rule invocation runs inside `std::panic::catch_unwind` with
`AssertUnwindSafe`. A rule that panics is recorded as a `RULE-004` diagnostic,
counted in `stats.rules_failed`, and its partial findings are discarded; the
remaining rules still run and the deterministic report is still produced. Panic
messages are shortened before they enter diagnostics and never include source
content. This makes hostile input or a buggy third-party rule a contained
failure rather than a scanner crash (`#103`).

## Finding de-duplication

After rules run, findings are ranked deterministically (see
[Finding ranking](finding-ranking.md)) and then collapsed with an overlap rule:

- Two findings are duplicates when they share the **same rule id and normalized
  file** and their inclusive line ranges overlap (for example `5..=9` and
  `7..=12`). Two single-line findings must also have overlapping column ranges,
  so distinct issues on the same line (such as two hardcoded addresses) are
  kept. Findings from different rules or files are never merged.
- Exactly one finding survives: the earliest start line wins, then the narrower
  span, then the smaller column, then the lexicographically smaller fingerprint.
  This keeps the earliest, most specific report entry.
- Adjacent ranges do not overlap (`1..=2` and `3..=4` both remain), and exact
  duplicates collapse to one entry.
- The rule is implemented by `deduplicate_overlapping` in
  `crates/soroban-scan-core/src/engine.rs`; unit tests cover overlapping,
  adjacent, cross-rule, cross-file, and exact-duplicate cases.

## Suppressions, baselines, and configuration

The scanner provides explicit mechanisms for reviewed exceptions:

- **Inline suppressions** exclude a finding from the gate while still reporting
  it, together with the directive and reason. See
  [Inline Suppressions](suppressions.md).
- **Baselines** separate new findings from known findings without hiding either.
  See [Baselines](baselines.md).
- **Rule and category filters** let a project choose which detectors run. See
  [Configuration](configuration.md).

None of these mechanisms changes the underlying evidence. They record a policy
decision; they do not make the code safe.

## Responsible use

- Treat findings as leads, not verdicts. Confirm the data flow, reachability,
  and intended business behavior.
- Keep the scanner's confidence honest when adding rules. A rule that cannot
  distinguish benign from dangerous patterns should be `low` confidence.
- Run the scanner in CI to catch regressions, not as the only security control.
- For high-value contracts, combine static analysis with tests, fuzzing, threat
  modeling, and an independent audit.

See [the rule system](rules/README.md) for detector details, the
[rule cookbook](rules/cookbook.md) for worked detection examples, and
[the security model](security/security-model.md) for the scanner's trust
boundaries.
