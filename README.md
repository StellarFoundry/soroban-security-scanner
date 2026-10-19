# Soroban Security Scanner

**Deterministic, evidence-based security analysis for Stellar Soroban smart contracts and Soroban-related Rust projects.**

[![CI](https://github.com/AyinkxLab/soroban-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AyinkxLab/soroban-security-scanner/actions/workflows/ci.yml)
[![Examples](https://github.com/AyinkxLab/soroban-security-scanner/actions/workflows/examples.yml/badge.svg)](https://github.com/AyinkxLab/soroban-security-scanner/actions/workflows/examples.yml)
[![Security Scan](https://github.com/AyinkxLab/soroban-security-scanner/actions/workflows/security-scan.yml/badge.svg)](https://github.com/AyinkxLab/soroban-security-scanner/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](https://www.rust-lang.org/)
[![Status: early development](https://img.shields.io/badge/status-early%20development-yellow.svg)](docs/PROJECT_STATUS.md)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

`soroban-scan` statically analyzes Soroban/Rust source code and reports security
findings with stable rule identifiers, severity and confidence ratings, precise
source locations, evidence, and remediation guidance.

The core scanner is **deterministic** and **AI-independent**. It never executes,
deploys, signs, or mutates the code it analyzes.

> **Project status:** early development. See [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md)
> for an honest, continuously updated description of what exists today.

---

## Why

Soroban smart contracts handle real value, and security review is still largely
manual and ad hoc. Generic Rust linters (`clippy`) do not understand Soroban
semantics, and general-purpose static analyzers do not model Soroban's
authorization, storage, and resource model.

`soroban-scan` fills that gap with focused, Soroban-aware detectors, a
deterministic rule engine, and CI-friendly machine-readable output (JSON, SARIF).

## Quickstart

```bash
git clone https://github.com/AyinkxLab/soroban-security-scanner
cd soroban-security-scanner
cargo build --release

# Scan a contract and print findings
./target/release/soroban-scan scan ./examples/vulnerable-contract --fail-on none

# Machine-readable output for CI
./target/release/soroban-scan scan . --format sarif --output results.sarif
```

Requires a stable Rust toolchain. See [`docs/development/setup.md`](docs/development/setup.md).

## What it detects

Thirteen Soroban-aware detectors ship today (from `SS-001` to `SS-029`). Severity
and confidence are independent and always reported honestly.

| Rule | Title | Severity | Confidence | Category |
| ---- | ----- | -------- | ---------- | -------- |
| [SS-001](docs/rules/detectors/SS-001.md) | State-changing entry point without caller authorization | high | medium | authorization |
| [SS-002](docs/rules/detectors/SS-002.md) | Cross-contract call without caller authorization | high | low | cross-contract |
| [SS-003](docs/rules/detectors/SS-003.md) | Unbounded storage iteration in an entry point | medium | low | resource-usage |
| [SS-004](docs/rules/detectors/SS-004.md) | Panic-prone construct in a contract entry point | low | medium | error-handling |
| [SS-005](docs/rules/detectors/SS-005.md) | Unsafe code in a Soroban contract | medium | high | unsafe |
| [SS-006](docs/rules/detectors/SS-006.md) | Persistent storage write without TTL management | low | low | storage |
| [SS-007](docs/rules/detectors/SS-007.md) | Hardcoded Stellar account or contract address | medium | low | configuration |
| [SS-008](docs/rules/detectors/SS-008.md) | Unchecked arithmetic in a contract entry point | medium | low | arithmetic |
| [SS-009](docs/rules/detectors/SS-009.md) | Insecure randomness derived from ledger state | medium | low | arithmetic |
| [SS-011](docs/rules/detectors/SS-011.md) | Initialization entry point without a re-initialization guard | high | low | access-control |
| [SS-013](docs/rules/detectors/SS-013.md) | Cross-contract call before state update | high | low | cross-contract |
| [SS-014](docs/rules/detectors/SS-014.md) | Token transfer amount without validation | medium | low | token |
| [SS-029](docs/rules/detectors/SS-029.md) | Public test or debug hook in a contract entry point | medium | medium | access-control |

Rule identifiers are stable (never reused or renumbered). See
[`docs/rules/README.md`](docs/rules/README.md) for the full rule system.

## Goals

- Detect real Soroban security problems (authorization, arithmetic, storage,
  resource usage, unsafe patterns, and more).
- Produce reproducible, evidence-based findings — never fabricated ones.
- Integrate cleanly with CI and GitHub code scanning via SARIF.
- Stay useful with no network access and no AI.
- Be safe to run on untrusted repositories.

## Non-goals

- The scanner does not replace professional security audits.
- The scanner does not execute or deploy contracts.
- The scanner does not require private keys, wallets, or network access.
- AI is never the authoritative security engine.

## Implemented today

- Deterministic project discovery and Soroban classification.
- `syn`-based Rust parsing with source locations.
- Thirteen security detectors (from `SS-001` to `SS-029`) with fixtures and documentation.
- CLI: `scan`, `rules`, `explain`, `version`, `init`, `config`.
- Output formats: terminal, JSON, SARIF 2.1.0, Markdown, and GitHub workflow annotations.
- Configurable rule selection, thresholds, and excludes.
- Baselines and incremental scanning (`--baseline`, `--write-baseline`,
  `--new-only`, `--incremental`).
- GitHub Actions security-scan workflow with SARIF upload.
- Composite GitHub Action and changed-file pull-request scanning.
- Opt-in sticky PR comments (one updated comment per PR) and check runs with
  structured inline annotations.
- Scheduled baseline refresh workflow that opens a reviewable pull request.
- CI compatibility matrix over pinned Soroban SDK 20.5.0, 21.7.7, and 29.0.1
  fixtures.
- Optional, clearly labeled assistance (`--guidance`); off by default and never
  authoritative.
- A compilable example suite: clean and intentionally vulnerable Soroban
  contracts (token, escrow, vault) plus a classic Stellar address example,
  built in CI.

## Usage

```bash
# Scan a project
soroban-scan scan ./contracts

# Machine-readable output
soroban-scan scan ./contracts --format json --output report.json --fail-on none
soroban-scan scan ./contracts --format sarif --output results.sarif

# Explore rules
soroban-scan rules
soroban-scan explain SS-001

# Configuration
soroban-scan init
soroban-scan config validate
```

See [`docs/cli.md`](docs/cli.md) for the full reference, including configuration
and stable exit codes.

## Demo

Scanning the intentionally vulnerable example (real output):

```console
$ soroban-scan scan examples/vulnerable-contract --fail-on none --quiet
high SS-001 src/lib.rs:23:9
low SS-006 src/lib.rs:23:9
low SS-004 src/lib.rs:30:9
medium SS-007 src/lib.rs:40:13
high SS-002 src/lib.rs:46:22
5 finding(s) — critical: 0, high: 2, medium: 1, low: 2, info: 0
```

Explore what a finding means:

```console
$ soroban-scan explain SS-001
SS-001 — State-changing entry point without caller authorization

Severity:   high
Confidence: medium
Category:   authorization
...
```

## Continuous integration & GitHub code scanning

Emit SARIF and upload it to GitHub code scanning, or use the bundled composite
Action to scan only the files changed in a pull request. See the
[GitHub Action reference](docs/github-action.md) for inputs, outputs and
examples, [`docs/github-integration.md`](docs/github-integration.md) for SARIF,
annotations and baselines, and [`action.yml`](action.yml) for the metadata.

```yaml
- uses: AyinkxLab/soroban-security-scanner@main
  with:
    fail-on: high
```

## Architecture

```
crates/
  soroban-scan-core   # deterministic analysis engine (library)
  soroban-scan-cli    # `soroban-scan` binary
tools/                # supporting tooling (Python)
fixtures/             # positive/negative security fixtures and corpus
examples/             # compilable clean + vulnerable Soroban contracts
docs/                 # architecture, development, security, rules, contributors
```

See [`docs/architecture/overview.md`](docs/architecture/overview.md) and the
[architecture decision records](docs/architecture/adr/).

## Security model

The scanner treats every scanned repository as **hostile input**. It does not
require or store keys, does not sign or submit transactions, does not execute
scanned code, and makes no network requests by default. See
[`SECURITY.md`](SECURITY.md) and [`docs/security/threat-model.md`](docs/security/threat-model.md).

The scanner is not an audit replacement. [Analysis
Methodology](docs/analysis-methodology.md) explains what the detectors can and
cannot prove, and how severity and confidence are assigned.

## Ecosystem

`soroban-scan` is built for the Stellar/Soroban ecosystem and is designed to sit
alongside the official toolchain:

- Stellar developer docs — <https://developers.stellar.org/>
- Soroban smart contracts guide — <https://developers.stellar.org/docs/smart-contracts>
- Stellar — <https://stellar.org/>

We aim to be listed among the community's Soroban developer tooling. If your
project would benefit from Soroban-aware static analysis in CI, open an issue and
we'll help wire it up.

## How this project is run

- **Maintainer:** [@Ayinkx](https://github.com/Ayinkx) (AyinkxLab).
- **Contribution flow:** issues are scoped with difficulty labels and clear
  acceptance criteria; PRs are reviewed before merge. This project participates
  in open-source contribution waves via [Drips Wave](docs/WAVE.md).
- **Releases:** tagged releases with a maintained [`CHANGELOG.md`](CHANGELOG.md).
- **Security:** please follow [`SECURITY.md`](SECURITY.md) for responsible
  disclosure.

## Documentation

- [Documentation index](docs/README.md)
- [Getting Started](docs/getting-started.md) · [Installation](docs/installation.md)
- [CLI Reference](docs/cli.md) · [Configuration](docs/configuration.md)
- [Rules](docs/rules/README.md) · [Baselines](docs/baselines.md)
- [GitHub Integration](docs/github-integration.md)
- [Observatory Integration](docs/integration/observatory.md) — the stable, versioned JSON/SARIF contract for downstream consumers such as the Stellar Contract Observatory.
- [Security Model](docs/security/security-model.md) · [Threat Model](docs/security/threat-model.md)
- [Architecture](docs/architecture/overview.md) · [Project Status](docs/PROJECT_STATUS.md)
- [Roadmap](docs/ROADMAP.md) · [Issue Backlog](docs/ISSUE_BACKLOG.md) · [Wave Board](docs/WAVE_BOARD.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributors](CONTRIBUTORS.md)

## Contributing

Contributions are welcome. Start with [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[contributor roadmap](docs/contributors/roadmap.md). Issues labelled
`good first issue` and `help wanted` are a good place to begin.

## License

[MIT](LICENSE) © 2026 AyinkxLab
