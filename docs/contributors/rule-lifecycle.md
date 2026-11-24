# Rule Lifecycle

This page describes how a detector moves from a proposal to a release. It
complements [Writing a Security Rule](writing-rules.md), which covers the
implementation steps in detail, and the
[pull request template](../../.github/PULL_REQUEST_TEMPLATE.md), whose checklist
mirrors the evidence required below.

```text
Proposal -> Fixture -> Implementation -> Review -> Release
```

## Who approves

| Stage | Approver | Where |
| ----- | -------- | ----- |
| Proposal | A maintainer | The proposal issue |
| Review | A maintainer; the code owners for `crates/soroban-scan-core/src/rules/` and `docs/rules/` | The pull request |
| Release | A maintainer cutting the release | [Release process](../development/release.md) |

Maintainers and code owners are listed in
[`GOVERNANCE.md`](../../GOVERNANCE.md) and
[`.github/CODEOWNERS`](../../.github/CODEOWNERS). Changes to severity or
confidence semantics, or to the rule framework itself, follow the ADR process in
`GOVERNANCE.md`.

## 1. Proposal

Open an issue (or comment on an existing one) before writing code, and ask to be
assigned. The proposal answers the four questions in
[step 0 of the writing guide](writing-rules.md#0-define-the-problem-before-writing-code):
problem, evidence, limitations, and false positives.

**Evidence required:** a concrete, statically detectable pattern, with at least
one real or realistic code snippet. If the evidence cannot be stated, the rule is
not ready; ambiguity is recorded in the proposal, not guessed.

**Approval:** a maintainer confirms the scope and the next free `SS-###`
identifier. Identifiers are never reused or renumbered.

## 2. Fixture

Add the corpus files before the detector:

- `fixtures/corpus/SS-XXX/positive.rs` must trigger the rule.
- `fixtures/corpus/SS-XXX/negative.rs` must not trigger it.

**Evidence required:** the negative fixture covers the legitimate patterns listed
under false positives in the proposal. Fixtures are parsed, not compiled, and
stay minimal and readable.

## 3. Implementation

Implement the detector, register it, and write the unit tests as described in
[Writing a Security Rule](writing-rules.md). Document it in
`docs/rules/detectors/SS-XXX.md` using the [rule template](../rules/TEMPLATE.md)
and add a row to the detector table in [`docs/rules/README.md`](../rules/README.md).

**Evidence required:** the local gate passes.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

The corpus test (`tests/corpus.rs`) and quality test (`tests/rule_quality.rs`)
pick the new rule up automatically. Confidence must be conservative, and the
detector must never fabricate findings or source locations.

## 4. Review

Open a pull request with `Closes #<issue-number>` and complete the
[pull request template](../../.github/PULL_REQUEST_TEMPLATE.md), choosing
"New security rule / detector" as the type of change.

**Evidence required:**

- Fixtures, unit tests, and the detector documentation are all present.
- The verification checklist and security checklist in the template are ticked
  and true.
- CI is green, including the documentation link check
  (`python tools/check_docs.py`).

**Approval:** a maintainer approves after the code owners for the rule and
documentation paths have reviewed. Review comments are resolved in the pull
request, not out of band.

## 5. Release

Merged rules ship with the next release. Add a `CHANGELOG.md` entry for the new
detector; the maintainer follows the [release process](../development/release.md).
A retired rule keeps its identifier and is marked deprecated rather than removed.
