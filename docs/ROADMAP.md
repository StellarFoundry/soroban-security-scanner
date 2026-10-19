# Roadmap

This is the public, high-level roadmap. Detailed, independently actionable work
lives in the issue backlog ([`ISSUE_BACKLOG.md`](ISSUE_BACKLOG.md)) and on GitHub.

## Now (v0.1.x)

The scanner is an MVP: deterministic analysis, thirteen detectors, CLI with
terminal/JSON/SARIF/Markdown output, baselines, CI integration, and a compilable
example suite.

Near-term priorities:

- Remove known false positives with interprocedural helper summaries
  ([#171](https://github.com/AyinkxLab/soroban-security-scanner/issues/171),
  [#172](https://github.com/AyinkxLab/soroban-security-scanner/issues/172),
  [#173](https://github.com/AyinkxLab/soroban-security-scanner/issues/173)).
- Inline suppression directives with auditable counts
  ([#174](https://github.com/AyinkxLab/soroban-security-scanner/issues/174),
  [#175](https://github.com/AyinkxLab/soroban-security-scanner/issues/175)).
- More Soroban detectors (SS-018 through SS-037).
- Release binaries and crates.io publishing.
- A pinned, CI-tested MSRV.

## Next

- Type-aware and data-flow analysis to raise confidence and cut noise.
- Deeper GitHub integration (check runs, sticky comments, reusable workflow).
- Expanded example contracts and a larger security regression corpus.
- Optional, clearly labeled assistance with network safeguards (off by default).

## Later

- Editor integration (diagnostics provider).
- Correlation of related findings and exploitability context.
- Community rule packs and severity profiles.

## Principles

- The deterministic engine is authoritative and always works without AI.
- No fabricated findings, source locations, or certainty.
- Safe on untrusted input: no execution, no network by default.
- Quality over issue count.

See [`PROJECT_STATUS.md`](PROJECT_STATUS.md) for what is implemented today.
