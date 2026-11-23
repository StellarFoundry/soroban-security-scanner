# Writing a Security Rule

This guide walks through adding a detector to the Soroban Security Scanner. Read
[`../rules/README.md`](../rules/README.md) first for the severity and confidence
semantics, then use the shared analysis primitives rather than re-deriving them:
[taint analysis](../taint-analysis.md) for caller-controlled data and
[control-flow graphs](../control-flow.md) for reachability. Finding order is
defined in [finding ranking](../finding-ranking.md). The full proposal-to-release
path, including who approves each stage, is in the
[rule review workflow](rule-review-workflow.md).

## 0. Define the problem before writing code

Answer these questions in the rule documentation:

1. **Problem** — what security problem does this address?
2. **Evidence** — what exactly is detectable statically?
3. **Limitations** — what can this detector not determine?
4. **False positives** — which legitimate patterns must not trigger it?

If you cannot state concrete evidence, the rule is not ready. Prefer not to
report over reporting uncertainly.

## 1. Choose an id

Use the next free `SS-###` identifier. Ids are never reused or renumbered.

## 2. Implement the detector

Create `crates/soroban-scan-core/src/rules/<name>.rs`:

```rust
use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-XXX",
    title: "Short title",
    description: "At least forty characters describing the problem and impact.",
    category: Category::Authorization,
    default_severity: Severity::High,
    default_confidence: Confidence::Medium,
    remediation: "What the developer should do.",
    references: &["https://example.com/reference"],
};

pub struct MyRule;

impl Rule for MyRule {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        for source in ctx.sources() {
            let Some(file) = &source.syntax else { continue };
            // Use rules::util helpers to extract facts, then decide.
        }
    }
}
```

Register it in `crates/soroban-scan-core/src/rules/mod.rs`:

```rust
mod my_rule;
registry.register(Box::new(my_rule::MyRule))?;
```

### Useful helpers

`crate::rules::util` provides:

- `contract_entry_functions(file)` — public/private functions in `#[contractimpl]`.
- `facts_from_block`, `facts_from_file` — method calls, function calls, macros,
  string literals, and `unsafe` locations.
- `location_for(ctx, source, line, column)` — builds a scan-relative location.
- `looks_like_stellar_address`.

Prefer the memoized `AnalysisContext` accessors in rules so facts are computed
once per scan: `ctx.facts_for_source(source)`, `ctx.facts_for_function(source,
&func)`, `ctx.helper_facts_for_function(source, &func)`,
`ctx.function_facts_for_source(source)`, and
`ctx.cast_facts_for_function(source, &func)`. The cache is keyed by source path
and function span, so facts never leak across files.

## 3. Add fixtures

Create:

```
fixtures/corpus/SS-XXX/positive.rs   # must trigger this rule
fixtures/corpus/SS-XXX/negative.rs   # must not trigger this rule
```

Fixtures are parsed, not compiled. Keep them minimal and readable.

## 4. Add tests

Add unit tests in your rule module using
`crate::rules::test_support::scan_rule`:

```rust
#[test]
fn flags_the_bad_case() {
    let findings = scan_rule(SRC, Box::new(MyRule));
    assert_eq!(findings.len(), 1);
}
```

The repository-level corpus test (`tests/corpus.rs`) and quality test
(`tests/rule_quality.rs`) automatically pick up new rules.

For three fully annotated examples that show the evidence and false-positive
judgment behind real detectors, see the [rule cookbook](../rules/cookbook.md).

## 5. Document the rule

Create `docs/rules/detectors/SS-XXX.md` from
[`../rules/TEMPLATE.md`](../rules/TEMPLATE.md), and add a row to the detector
table in [`../rules/README.md`](../rules/README.md).

## 6. Validate

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

`RuleRegistry::with_default_rules()` validation will fail if metadata or docs
are missing. The review, approval, and release stages are documented in the
[rule review workflow](rule-review-workflow.md).

## Rules of the road

- Never fabricate findings or source locations. The engine rejects locations
  outside the analyzed file set.
- Evidence must be concrete and reproducible.
- Be conservative with confidence.
- Never execute, build, or deploy scanned code.
