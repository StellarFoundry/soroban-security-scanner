# Architecture Overview

This document describes the intended architecture of the Soroban Security
Scanner. It is updated as the implementation matures.

## Guiding principles

1. **Deterministic** — the same input always yields the same findings, in the
   same order. No wall-clock, randomness, or filesystem-order dependence in rule
   evaluation or output.
2. **Evidence-based** — a finding exists only if a rule observed concrete
   evidence in the source. Rules cannot invent findings or locations.
3. **Non-executing** — scanned code is never compiled, run, deployed, or
   mutated. Scanned repositories are hostile input.
4. **AI-optional** — the deterministic engine is authoritative. AI assistance,
   if enabled, is clearly labeled and advisory.
5. **Modular** — discovery, parsing, rules, engine, and reporting are separate
   concerns with stable interfaces.

## Workspace layout

```
crates/
  soroban-scan-core/     # deterministic analysis engine (library)
  soroban-scan-cli/      # `soroban-scan` binary
tools/                   # Python supporting tooling (non-critical path)
fixtures/                # positive/negative fixtures and security corpus
docs/                    # architecture, development, security, rules, contributors
```

## Core pipeline

```
discovery ──▶ parsing ──▶ analysis context ──▶ rule engine ──▶ findings ──▶ reporting
   │             │                                  │
   │             │                                  ├─ terminal
   │             │                                  ├─ JSON
   │             │                                  ├─ SARIF
   │             │                                  └─ Markdown
   │             │
   └─ Cargo.toml / workspace / Soroban dependency detection
                 └─ syn-based AST parsing with source spans
```

### 1. Discovery

Locates repositories, `Cargo.toml` manifests, workspaces, and Rust source files.
Classifies a project as **generic Rust**, **likely Soroban**, or **confirmed
Soroban** based on evidence (Soroban dependencies, `#[contract]` /
`#[contractimpl]` attributes). Refuses to classify arbitrary Rust projects as
Soroban without evidence.

### 2. Parsing

Parses source with `syn`, retaining source spans (line/column) via
`proc-macro2` with span locations enabled. Parser failures are non-fatal: the
scanner reports diagnostics and continues where safe. No code is executed.

### 3. Analysis context

A read-only context assembled from the project model and parsed sources. Rules
receive the context and emit findings. The context is immutable during a scan,
which keeps results deterministic.

### 4. Rule engine

Rules implement a common trait and register with a registry. Each rule declares
metadata (id, title, category, default severity, default confidence, references).
The engine runs enabled rules, collects findings, sorts them deterministically,
and applies suppressions and baselines.

### 5. Reporting

Findings are rendered to terminal, JSON, SARIF, and Markdown. Machine-readable
formats are stable and versioned.

## Finding model

Every finding carries: rule id, title, description, severity, confidence,
category, file, line, column (when available), evidence, remediation, and
references. See `docs/rules/README.md` for severity and confidence definitions.

## Configuration

Configuration is layered and validated. Repository-provided configuration is
treated as untrusted input and never grants capabilities (for example, it cannot
enable network access or arbitrary code execution).

## Dependencies

Dependencies are intentionally minimal and justified. See
[ADR-0001](adr/0001-rust-core-python-tooling.md),
[ADR-0002](adr/0002-severity-and-confidence.md),
[ADR-0003](adr/0003-determinism-contract.md),
[ADR-0004](adr/0004-error-handling-strategy.md),
[ADR-0005](adr/0005-dependency-justification-policy.md), and `deny.toml`.
Lockfiles are committed for reproducible builds.

## Further reading

- [Workspace layout and module dependency map](workspace-layout.md)
- [ADRs](adr/)
- [Security model](../security/security-model.md)
- [Threat model](../security/threat-model.md)
- [Rule development](../rules/README.md)
