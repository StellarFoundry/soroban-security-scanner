# Rule template

Copy this template to `docs/rules/detectors/SS-XXX.md` and fill in every
section. Then implement the detector, add fixtures, and add tests. See
[`../contributors/writing-rules.md`](../contributors/writing-rules.md) for the
full process.

```markdown
# SS-XXX — <Short, specific title>

- **Severity:** <info|low|medium|high|critical>
- **Confidence:** <low|medium|high>
- **Category:** <authorization|authentication|access-control|cross-contract|token|storage|arithmetic|error-handling|events|resource-usage|configuration|dependencies|unsafe>

## Problem

What security problem does this address, and what is the impact if the issue is
real?

## How it is detected

The exact, concrete evidence the detector observes. Name the AST features and
patterns. Be precise about what must be present for a finding.

## Limitations

What the detector cannot determine. Explicitly state that it is syntactic if it
is.

## False positives

Legitimate patterns that must not (and do not) trigger the rule.

## Remediation

What a developer should do, with a small concrete example where useful.

## References

- <https://...>
```

## Review checklist

Complete the full [rule quality checklist](quality-checklist.md) in your pull
request description. At a minimum, before opening a pull request:

- [ ] The id is new, unique, and never reused.
- [ ] `severity` and `confidence` are honest. High-severity heuristic findings
      use `confidence: low` or `medium` (never `critical` + `high`).
- [ ] Description is at least 40 characters and clearly states impact.
- [ ] Remediation is actionable.
- [ ] At least one reference is provided.
- [ ] `fixtures/corpus/<ID>/positive.rs` triggers exactly this rule.
- [ ] `fixtures/corpus/<ID>/negative.rs` does not trigger it.
- [ ] This documentation file exists at `docs/rules/detectors/<ID>.md`.
- [ ] `cargo test --all` and `cargo clippy --all-targets --all-features -- -D warnings` pass.
