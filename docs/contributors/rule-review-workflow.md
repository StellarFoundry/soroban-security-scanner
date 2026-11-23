# Rule review workflow

This page describes the path a built-in security rule takes from proposal to
release: who decides at each stage, and what evidence the review needs. It
complements the hands-on [writing a security rule](writing-rules.md) guide and
the rule catalog in [`../rules/README.md`](../rules/README.md).

Roles are defined in [`GOVERNANCE.md`](../../GOVERNANCE.md): a **contributor**
opens issues and pull requests, a **reviewer** can approve but not merge, and a
**maintainer** assigns issues, merges, and cuts releases. Review routing for
security-sensitive paths lives in [`.github/CODEOWNERS`](../../.github/CODEOWNERS).

## Stages

| Stage | Owner | Decision maker | Required evidence |
| ----- | ----- | -------------- | ----------------- |
| 1. Proposal | Contributor | Maintainer triage | A problem statement and concrete static evidence |
| 2. Assignment | Maintainer | Maintainer | The issue is assigned to one contributor |
| 3. Fixtures | Contributor | Reviewer | Positive, negative, adversarial, and must-trigger samples |
| 4. Implementation | Contributor | Reviewer and `CODEOWNERS` owner | Detector, tests, docs, and a clean local gate |
| 5. Review | Reviewer | Maintainer | Approvals, green CI, and the PR checklist |
| 6. Release | Maintainer | Maintainer | Changelog entry and a tagged, green release |
| 7. Deprecation | Maintainer | Maintainer and `CODEOWNERS` owner | A replacement and a public notice; the id is retained |

## 1. Proposal

Open an issue before writing code. A new detector uses the feature request
template; a missed detection or false positive uses the
[security regression template](../../.github/ISSUE_TEMPLATE/security_regression.yml)
and includes the rule id, a minimal snippet, the expected result, the actual
result, and the SDK and scanner versions.

The issue must answer the four questions in
[writing a rule](writing-rules.md#0-define-the-problem-before-writing-code):

1. **Problem** — the security impact.
2. **Evidence** — what is detectable statically.
3. **Limitations** — what the detector cannot determine.
4. **False positives** — legitimate patterns that must not trigger.

A maintainer triages the issue and either accepts it, asks for more evidence, or
declines it. If the evidence is not concrete, the rule is not ready. Rule
semantics, severity, and confidence are security-sensitive decisions, so the
relevant `CODEOWNERS` owner must agree before implementation starts.

## 2. Assignment

A maintainer assigns the issue to one contributor. Assignment is required before
a pull request: it prevents duplicate work and keeps the review queue honest.
The assignment process for open-source waves is in [`../WAVE.md`](../WAVE.md).

The issue should carry a `difficulty/*` label where the wave process applies.
Contributors do not self-assign a rule that changes detection semantics without
maintainer agreement.

## 3. Fixtures

The contributor writes the corpus before or alongside the detector:

- `fixtures/corpus/<ID>/positive.rs` — must trigger the rule.
- `fixtures/corpus/<ID>/negative*.rs` — at least three files that must not
  trigger it, covering the documented false positives.
- `fixtures/corpus/<ID>/expected.json` — the exact per-file finding counts.
- `fixtures/adversarial/<ID>/sample.rs` — unusual but valid syntax, with an
  entry in `fixtures/adversarial/expectations.toml`.
- `fixtures/must-trigger/<ID>.rs` — one known-vulnerable sample, with an entry
  in `fixtures/must-trigger/manifest.toml`.
- `docs/rules/detectors/<ID>.md` and a row in `docs/rules/README.md`.

The id must be the next free `SS-###` identifier. Ids are never reused or
renumbered, including ids retired in the past.

Regenerate manifests only for an intentional change, review the diff, and say
why the counts changed in the pull request:

```bash
UPDATE_EXPECTATIONS=1 cargo test -p soroban-scan-core --test corpus
UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test finding_counts --test report_snapshots
```

On PowerShell, set the variable first, for example
`$env:UPDATE_EXPECTATIONS="1"`, and remove it afterwards.

Reviewers check that the negative fixtures cover the documented false positives,
not merely easy cases, and that the positive fixture is the smallest source that
demonstrates the problem.

## 4. Implementation

The detector lives in `crates/soroban-scan-core/src/rules/<name>.rs`, is
registered in `rules/mod.rs`, and uses the shared facts and CFG helpers rather
than re-deriving syntax. It needs unit tests in the module and the repository
tests pick it up automatically.

The contributor runs the full local gate:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
python tools/check_docs.py
python -m unittest discover -s tests
```

`python tools/check_docs.py` verifies relative Markdown links, and
`python -m unittest discover -s tests` runs the repository tooling tests. Both
are required before review.

The documentation is part of the implementation: severity, confidence,
limitations, false positives, and remediation must match what the detector
actually does. `cargo run -p xtask -- rule SS-XXX "Title"` scaffolds the
conventional files when a contributor wants a starting point.

## 5. Review

A reviewable pull request states the change and includes `Closes #<issue>` in the
description, as the [pull request template](../../.github/PULL_REQUEST_TEMPLATE.md)
requires. The author ticks the template's verification boxes and the security
checklist:

- no secrets, credentials, or private keys;
- no scanned code is executed, built, or deployed;
- no new network access by default;
- the scanned repository is still treated as untrusted input;
- new dependencies are justified.

Who approves:

- A **reviewer** can approve a pull request but cannot merge it.
- A **maintainer** merges, and at least one maintainer approval plus a green CI
  run is required.
- Changes under `crates/soroban-scan-core/src/rules/`, `engine.rs`, `rule.rs`,
  `severity.rs`, `confidence.rs`, `suppression.rs`, `docs/rules/`, and
  `.github/workflows/` also need approval from their `CODEOWNERS` owner.
- Security-sensitive rule semantics are not decided by a contributor majority;
  the relevant `CODEOWNERS` owner must approve them.

The reviewer checks the problem, evidence, limitations, and false positives
against the fixtures, and confirms the gate commands above pass. Requested
changes are addressed in the same pull request; a rule that no longer matches
its documentation is not merged.

## 6. Release

A maintainer cuts the release following
[the release process](../development/release.md). New detectors normally ship in
a **minor** release. The release checklist requires:

- the full local gate and green CI;
- a `CHANGELOG.md` entry for the release;
- the workspace version bump and the release commit;
- an annotated tag, which triggers the publish workflow.

The changelog and GitHub release notes are the public record that a rule shipped.
After release, the rule id and its documented behaviour are a compatibility
surface: `docs/api-stability.md` and [`../releases.md`](../releases.md) govern
changes to it.

## 7. Deprecation

A rule is retired when it is superseded, duplicated, or no longer supported. A
maintainer announces the change in the `CHANGELOG.md` entry and the release
notes. Where practical the old form keeps working for at least one minor release,
and the replacement is documented in the same change.

A retired rule keeps its `SS-###` identifier forever and is marked deprecated;
the number is never reassigned to a different check. Removing a rule is a
breaking change governed by [`../releases.md`](../releases.md), and it needs the
same `CODEOWNERS` approval as adding one.

## Quick checklist

- [ ] The issue describes problem, evidence, limitations, and false positives.
- [ ] A maintainer assigned the issue and the next free id is used.
- [ ] The positive, three or more negative, adversarial, and must-trigger
      fixtures exist and the expectations are regenerated deliberately.
- [ ] Unit tests and the repository tests pass.
- [ ] The detector documentation and `docs/rules/README.md` row match the
      implementation.
- [ ] The full local gate and `python` checks pass.
- [ ] The pull request uses the template, includes `Closes #<issue>`, and has the
      required approvals.
- [ ] The changelog entry exists for the release that ships the rule.
