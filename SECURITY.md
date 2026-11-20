# Security Policy

This policy covers the **Soroban Security Scanner tooling itself**. If you want
to report a security finding in a *scanned target*, that is a different matter —
see "Scope" below.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** using GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
for this repository, or email **olayinkaawal00@gmail.com**.

**Do not open a public issue for a security vulnerability.**

Please include:

- A description of the issue and its impact.
- Reproduction steps or a proof of concept.
- Affected version/commit.
- Any suggested remediation.

## What to expect

- **Acknowledgement** within 5 business days.
- **Assessment and triage** within 10 business days.
- Coordinated disclosure: we will agree on a disclosure timeline with you.
- Credit in the release notes (unless you prefer to remain anonymous).

## Supported versions

The project is pre-1.0. Security fixes are applied to the latest released
`0.x` minor line and to `main`. Older minors are not backported by default.
See [Releases and support](docs/releases.md) for the full policy.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| 0.1.x   | No        |

## Scope

In scope (vulnerabilities in this project):

- Report generation that leaks secrets, environment variables, or absolute
  paths unintentionally.
- Path traversal, symlink escape, or sandbox boundary bypass during scanning.
- Denial of service triggered by malformed input (panics, unbounded memory).
- Supply-chain issues introduced by this project's dependencies.
- Insecure handling of configuration or baselines.

Out of scope:

- Vulnerabilities in third-party code that the scanner merely *reports*.
- Vulnerabilities in scanned contracts (report those to the contract's owners).
- Findings that are already documented as known limitations.

## Security model

The scanner is designed to run safely on untrusted source code. It does not
require private keys, does not sign or submit transactions, does not execute
scanned code, and makes no network requests by default. See
[`docs/security/threat-model.md`](docs/security/threat-model.md) and
[`docs/security/security-model.md`](docs/security/security-model.md).
