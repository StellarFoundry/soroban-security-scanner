# Taint Assumptions and Limitations

Rule authors need to know what the scanner can and cannot prove about how
caller-controlled data flows through a contract. This document states the model
honestly so that rules and their documentation do not over-claim.

> **There is no general taint engine.** `soroban-scan` does not build a
> data-flow graph, a call graph across files, or a path-sensitive model. What it
> has are a few **syntactic, intraprocedural heuristics** that recognize
> *direct* uses of function parameters. Every finding built on them is reported
> at `confidence: low` unless the evidence is stronger than the heuristic.

This page complements [Analysis Methodology](../analysis-methodology.md). Where
the two differ in detail, the source code and tests listed under
[Where the behavior is tested](#where-the-behavior-is-tested) are authoritative.

## Sources

A *source* is a value the scanner treats as caller-controlled or otherwise
untrusted.

| Source | Recognized as | Used by |
| ------ | ------------- | ------- |
| Parameter of a **public** function in a `#[contractimpl]` block | Any plain-identifier parameter whose type is not `Env` (a leading `&` is ignored) | SS-031, SS-018, SS-014 |
| Value read from contract storage (`...storage()...get(...)`) | A `let` binding whose initializer text contains `storage` and `get`/`get_unchecked` | SS-018 (as an *origin*, not as caller input) |

Not sources:

- Parameters of private functions and helpers. Only public entry points are
  visited.
- Destructured parameters (`(a, b): (u32, u32)`); only plain identifier patterns
  are recorded.
- Return values of other contracts, ledger data, and values deserialized from
  `Bytes`/`Val` conversions.
- Struct fields or collection elements that merely contain a parameter.

## Sinks

A *sink* is a program point where a source matters. Sinks are fixed per rule;
there is no user-extensible sink list.

| Rule | Sink | Source required there |
| ---- | ---- | --------------------- |
| SS-031 | First argument (the topic list) of `.publish(...)` whose receiver text contains `event` | Any identifier in the expression that names a caller parameter |
| SS-018 | An `expr as Type` narrowing integer cast | The operand is *directly* a parameter or a storage-read local |
| SS-014 | Amount argument of `transfer` / `transfer_from` | The amount is *directly* a parameter that has no zero comparison |

## Propagation

The scanner propagates very little:

- **Within one expression**, SS-031 collects every parameter identifier
  reachable anywhere in the topic expression, including inside tuples,
  references, method calls, and function-call arguments. `(symbol_short!("t"),
  &account)` and `tag_of(account)` both count as referencing `account`.
- **Through `let` bindings**, only SS-018 records the binding, and only to learn
  the binding's declared or inferred *type* and whether it came from a storage
  read. A local derived from a parameter (`let x = amount + 1;`) is classified
  as a plain local and is **not** traced back to `amount`.
- **Through parentheses, groups, and `&`**, origin classification looks through
  them (`&amount`, `(amount)`).
- **Through helper functions**, the scanner does not propagate values. It only
  merges *facts* (calls, macros, arithmetic) from same-file helpers so that
  presence checks such as `require_auth` or a TTL call can be satisfied by a
  helper. Argument-to-parameter binding is never modeled.

Anything not listed above is not propagated.

## Sanitizers

A *sanitizer* is an operation after which a value is no longer considered
dangerous.

- **There is no general sanitizer model.** Wrapping a parameter in a function
  call, a conversion, or a validation helper does not clear it. For SS-031,
  `tag_of(account)` is still reported.
- **SS-014** recognizes one sanitizer: a comparison of the amount parameter
  against zero (`amount <= 0`, and the mirrored `0 >= amount`) in the analyzed
  block.
- **SS-018** treats a type-wide cast as safe by construction (same-width and
  widening casts are ignored), but a prior range check does not suppress a
  narrowing finding.
- Allowlist checks, `require_auth`, and `assert!`/`panic!` guards are **not**
  recognized as sanitizers for taint purposes.

Because sanitizers are mostly unmodeled, the scanner errs toward reporting a
possible issue at low confidence rather than silently trusting a check it cannot
interpret.

## Path sensitivity

The scanner is **path-insensitive and flow-insensitive** for values:

- Branch conditions are not evaluated. A parameter used only in the `else`
  branch of a guard is reported the same as one used unconditionally.
- Statement order is not used to decide whether a value was checked *before* it
  reached a sink, except where a rule explicitly documents an ordering check
  (for example SS-013 and SS-017, which compare call positions, not data flow).
- Loops are visited once; there is no fixed-point iteration.
- Early returns and `?` do not remove later statements from consideration.

A finding therefore means "a matching construct exists in the function", not "a
tainted value reaches the sink on a feasible path".

## Truncation and bounds

The scanner is bounded on purpose. Every bound makes it miss flows rather than
invent them.

| Bound | Value | Effect |
| ----- | ----- | ------ |
| Helper walk depth | `HELPER_SUMMARY_MAX_DEPTH` = 3 | Facts from helpers more than three calls from the entry point are not merged. |
| Helper scope | Same file only | Calls into other files, crates, or contracts are not followed. |
| Duplicate helper names | First definition in source order wins | A later same-named function is ignored. |
| Cycles | Each function is visited once | Recursive helpers are summarized once. |
| Evidence text | Truncated (for example to 160 characters) | Only the displayed excerpt is shortened; detection is not affected. |
| Macros | Token streams are opaque | Values used inside macro bodies are not inspected. |

When a bound is hit, the scanner stops expanding silently. It does not guess the
missing part of the flow.

## Ambiguity is recorded, not guessed

The scanner never fabricates edges, locations, or findings. When it cannot tell
where a value came from (an operand's type is not visible, a helper lives in
another file, a macro hides the expression), the result is **no finding** or a
**low-confidence finding with the exact evidence it saw**, never a stronger claim.
Rule authors must keep to the same rule: if a heuristic cannot decide, prefer
`confidence: low` or do not report. See
[Rules: confidence](../rules/README.md#confidence).

## Supported and unsupported flows

The examples below match the corpus and unit tests for SS-031 and SS-018.

### Supported: parameter used directly in an event topic (SS-031)

```rust
pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
    env.events()
        .publish((symbol_short!("transfer"), to), (from, amount)); // reported
}
```

`to` appears in the topic list, so the finding is reported.

### Supported: parameter nested in a call or reference (SS-031)

```rust
env.events().publish((symbol_short!("tag"), &account), 0); // reported
env.events().publish(tag_of(account), 0);                   // reported
```

Any parameter identifier inside the topic expression counts.

### Not reported: constant topic, parameter only in the payload (SS-031)

```rust
env.events()
    .publish(symbol_short!("transfer"), (from, to, amount)); // not reported
```

### Unsupported: parameter laundered through a local (SS-031)

```rust
pub fn announce(env: Env, account: Address) {
    let topic = account.clone();
    env.events().publish(topic, 0); // NOT reported: `topic` is not a parameter name
}
```

This is a false negative by design. The scanner does not follow `topic` back to
`account`.

### Unsupported: flow through a helper (SS-031, SS-018)

```rust
pub fn entry(env: Env, amount: i128) {
    let small = narrow(amount);     // NOT reported
}
fn narrow(v: i128) -> u32 { v as u32 }
```

`narrow` is private and not an entry point, so its body is not visited as a sink
scope, and the argument-to-parameter binding is never modeled.

### Supported: direct narrowing cast of a parameter (SS-018)

```rust
pub fn set(env: Env, amount: i128) {
    let small = amount as u32; // reported: parameter, 128 -> 32 bits
}
```

### Unsupported: derived operand (SS-018)

```rust
let doubled = amount * 2;
let small = doubled as u32; // NOT reported: `doubled` is a plain local
```

## Guidance for rule authors

- Describe your rule's source, sink, and sanitizer in its detector document
  under **How it is detected** and **Limitations**, using this page's terms.
- Do not describe a rule as "taint analysis" or claim "all flows". Say "direct
  uses of a parameter".
- Document the false negatives above that apply to your rule.
- Add a corpus fixture for each supported flow and an adversarial fixture for
  each unsupported flow you rely on staying unreported.
- Keep confidence at `low` for heuristics that cannot see sanitizers.

## Where the behavior is tested

| Behavior | Location |
| -------- | -------- |
| SS-031 sources, sinks, constants, payload, private helpers | Unit tests in `crates/soroban-scan-core/src/rules/user_controlled_event_topic.rs`; fixtures under `fixtures/corpus/SS-031/` and `fixtures/adversarial/SS-031/` |
| SS-018 parameter and storage-read origins | Unit tests in `crates/soroban-scan-core/src/rules/unchecked_integer_cast.rs`; fixtures under `fixtures/corpus/SS-018/` |
| SS-014 zero-comparison sanitizer and non-parameter amounts | Unit tests in `crates/soroban-scan-core/src/rules/token_transfer_amount.rs` |
| Helper depth, cycles, same-file scope | `HELPER_SUMMARY_MAX_DEPTH` and `facts_with_helpers_from_with_imports` in `crates/soroban-scan-core/src/rules/util.rs` |
