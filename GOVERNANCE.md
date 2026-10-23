# Governance

This project is small and moves quickly. Governance is deliberately
lightweight: just enough structure that contributors know who decides what, how
significant decisions are recorded, and what happens when people disagree.

It complements, and does not replace, [`CONTRIBUTING.md`](CONTRIBUTING.md),
the [Code of Conduct](CODE_OF_CONDUCT.md), and the
[contributor roadmap](docs/contributors/roadmap.md).

## Roles

| Role | Who | Responsibilities |
| ---- | --- | ---------------- |
| **Contributor** | Anyone who opens an issue, pull request, or review. | Follows [`CONTRIBUTING.md`](CONTRIBUTING.md) and the Code of Conduct. No approval needed to participate. |
| **Reviewer** | A contributor who has landed several accepted changes and is invited by a maintainer. | Reviews pull requests and triages issues. Can approve, but not merge. |
| **Maintainer** | Listed in [`.github/CODEOWNERS`](.github/CODEOWNERS) and the repository's GitHub team. | Merges pull requests, assigns issues, cuts releases, owns security-sensitive paths, and keeps the roadmap honest. |

Roles are earned through sustained, high-quality contributions and are granted
by existing maintainers by consensus. A maintainer who is inactive for six
months may be moved to emeritus status by the remaining maintainers; they can
return on request.

Maintainers follow the response targets in [`docs/WAVE.md`](docs/WAVE.md):
an initial response within 48 hours and a review decision within 72 hours of a
reviewable pull request.

## Everyday decisions

Most changes (bug fixes, new fixtures, documentation, rules that follow the
[rule-writing guide](docs/contributors/writing-rules.md)) need only a normal
pull request: one maintainer approval, a green CI run, and the local gate in
[`CONTRIBUTING.md`](CONTRIBUTING.md). Paths listed in `CODEOWNERS` also need
review from their owner.

## Architecture Decision Records (ADRs)

Decisions that are expensive to reverse are recorded as ADRs under
[`docs/architecture/adr/`](docs/architecture/adr/README.md). Write an ADR when a
change:

- alters a documented contract (determinism, severity and confidence
  semantics, output schemas, public API stability);
- adds or removes a significant dependency (see
  [ADR-0005](docs/architecture/adr/0005-dependency-justification-policy.md));
- changes the project's scope, supported platforms, or release policy; or
- changes this governance document.

Process:

1. Open an issue describing the problem and the options considered.
2. Submit a pull request adding the next free ADR number, with context, the
   decision, and its consequences, and link it from the ADR index.
3. Allow at least **seven days** for discussion unless the change is urgent
   (for example a security fix), in which case the maintainers say why the
   window was shortened.
4. Status is `Proposed` while open and `Accepted` once merged. A superseded ADR
   is kept and marked `Superseded by ADR-NNNN`; ADRs are not rewritten.

## Deciding contentious changes

When contributors or maintainers disagree:

1. **Discuss in the open**, on the issue or pull request, with arguments tied
   to the project's goals: honest findings, determinism, and a small, auditable
   dependency surface.
2. **Seek consensus.** Maintainers try to resolve the disagreement by
   addressing every concern raised, or by narrowing the change.
3. **Call for a vote** if consensus is not reached after the discussion
   window. Any maintainer may ask for one. Each maintainer has one vote, and a
   simple majority of the maintainers who vote decides. Voting stays open for
   at least seven days and is recorded on the issue or ADR pull request.
4. **Tie-break.** If the vote is tied, the lead maintainer decides and states
   the reasoning in writing.
5. **Record it.** Significant outcomes are captured in an ADR so the
   reasoning outlives the thread. Decisions can be revisited when there is new
   information, not simply because someone disagrees.

Security-sensitive decisions (rule semantics, severity and confidence
defaults, anything affecting what the scanner reports as safe) require approval
from the relevant `CODEOWNERS` owner and are not decided by a contributor
majority alone.

Conduct concerns are handled under the [Code of Conduct](CODE_OF_CONDUCT.md),
and vulnerabilities under [`SECURITY.md`](SECURITY.md), never in a public vote.

## Changing this document

Changes to `GOVERNANCE.md` follow the ADR process above.
