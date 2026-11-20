# Adversarial fixtures

Each built-in detector has at least one adversarial sample here. A sample uses
valid but unusual Rust: macros, aliases, raw strings and identifiers, whitespace
inside paths and method chains, split expressions, and inline manifest tables.
The point is to pin what a detector does when syntax is legal but not written
the way the rule documentation shows.

`expectations.toml` is the source of truth. Every rule in the registry must have
exactly one entry:

```toml
[SS-001]
file = "SS-001/spaced_chain.rs"
expect = "trigger"
why = "What the sample proves, or which limit it documents."
```

- `trigger`: the rule must report at least one finding.
- `no-trigger`: the rule must report nothing. Use this only to document a known
  heuristic limit, and say so in `why`.

`crates/soroban-scan-core/tests/adversarial_corpus.rs` derives the rule list
from `RuleRegistry::with_default_rules()`, so adding a detector without a
fixture fails the suite. It also rejects entries for unknown rules, missing
files, and unknown `expect` values.

Add a new detector's sample as `fixtures/adversarial/<RULE-ID>/<case>.rs` (or
`.toml` for SS-015), then add its entry. Keep samples synthetic: no real
contracts, secrets, keys, or addresses.
