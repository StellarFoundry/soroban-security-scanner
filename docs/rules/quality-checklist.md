# Rule quality checklist

Use this checklist for every pull request that adds or changes a security rule.
Authors tick it before opening the PR; reviewers use it to review consistently.
It is deliberately short. For the full process see
[`../contributors/writing-rules.md`](../contributors/writing-rules.md), and for
the severity and confidence definitions see [`README.md`](README.md).

Copy the list below into the PR description and mark each item. If an item does
not apply, write `N/A` and say why.

## Evidence

- [ ] The rule states the concrete, statically observable evidence that
      triggers it, and what is **not** observable.
- [ ] Every finding carries an exact `evidence` excerpt and a real source
      location. Nothing is inferred, invented, or guessed.
- [ ] Where the analysis is ambiguous (unresolved call, macro, dynamic
      dispatch), the ambiguity is recorded as a limitation or diagnostic, not
      resolved by assumption. No edges or findings are fabricated.

## Confidence justification

- [ ] `severity` and `confidence` are set independently (see
      [`README.md`](README.md)).
- [ ] The rule page explains in a sentence or two **why** this confidence level
      is warranted. Heuristic rules use `low` or `medium`, never `high`.
- [ ] Known false-positive patterns are listed, and each has a negative fixture
      or test.

## Tests

- [ ] `fixtures/corpus/<ID>/positive.rs` triggers exactly this rule.
- [ ] `fixtures/corpus/<ID>/negative.rs` does not trigger it.
- [ ] Unit and regression tests cover the main logic and each false-positive
      case.
- [ ] An adversarial sample (malformed, hostile, or unusual input) is added and
      the scanner neither panics nor reports fabricated results.

## Docs

- [ ] `docs/rules/detectors/<ID>.md` follows [`TEMPLATE.md`](TEMPLATE.md) with
      every section filled in.
- [ ] The rule is added to the table in [`README.md`](README.md).
- [ ] Remediation is actionable and has at least one reference.
- [ ] `CHANGELOG.md` is updated.

## Security considerations

- [ ] The rule only reads and parses source. It never executes, builds, or
      fetches scanned code.
- [ ] The scanned repository is still treated as untrusted input (bounded
      work, no unbounded recursion or allocation).
- [ ] No new dependency, or it is justified per
      [ADR-0005](../architecture/adr/0005-dependency-justification-policy.md).

## Local gate

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo test --all`
