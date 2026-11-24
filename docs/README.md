# Documentation

Start here.

## Getting started

- [Installation](installation.md) — build and install the scanner.
- [Getting Started](getting-started.md) — your first scan.
- [Upgrading](upgrading.md) — dry run, compatibility, rollback, and unsupported upgrades.
- [CLI Reference](cli.md) — every command, option, and exit code.
- [Configuration](configuration.md) — configuration file reference.
- [Doctor](doctor.md) — explain classification, excludes, and effective configuration.
- [Inline Suppressions](suppressions.md) — suppress one finding with a source comment.

## Using the scanner

- [Rules](rules/README.md) — severity, confidence, and the built-in detectors.
- [Analysis Methodology](analysis-methodology.md) — what static analysis can and cannot prove.
- [Type Model](type-model.md) — which type names and cast source types are modeled, and their limits.
- [Taint Analysis](taint-analysis.md) — source/sink descriptors, propagation, sanitizers, and limits.
- [Control-flow graphs](control-flow.md) — per-function nodes, edges, spans, and reachability.
- [Finding ranking](finding-ranking.md) — how severity, confidence, reachability, and span order output.
- [Baselines](baselines.md) - track new vs. known findings.
- [Policy and Reporting](policy.md) - policy schema, precedence, waivers, and report formats.
- [Rule Pack Signing and Verification](rule-pack-signing.md) - detached Ed25519 signatures, keyrings, and verification.
- [Rule Pack CLI](rule-pack-cli.md) - install, list, update, and remove local packs with a deterministic lockfile.
- [Rule Pack Sandboxing](pack-sandboxing.md) - wall-clock, output, and rule-count limits for community packs.
- [Rule Pack Moderation](pack-moderation.md) - review criteria, reporting, and removal policy.
- [Report Retention](retention.md) - deterministic artifact names and retention guidance.
- [In-process scan service](service-api.md) - bounded job storage for an embedding service.
- [Deploying the scan API adapter](api-deployment.md) - configuration, TLS, storage, health checks, and public-exposure warnings.
- [GitHub Integration](github-integration.md) — Action, SARIF, PR scanning.
- [GitHub Action](github-action.md) — inputs, outputs, and usage examples.
- [CI Recipes](ci-recipes.md) — copy-paste snippets for common CI systems and hooks.
- [Observatory Integration](integration/observatory.md) — the stable, versioned report contract.
- [TypeScript API client](../clients/typescript/README.md) - typed client for the scan API in [service-api.md](service-api.md): submit, poll, fetch report.
- [Optional AI Assistance](ai.md) — off by default, never authoritative.
- [AI privacy and data flow](ai-privacy.md) — exactly what can leave the machine.
- [Opt-in telemetry](telemetry.md) — off by default; bounded event schema and retention.
- [FAQ](faq.md) — common questions about false positives, CI gating, and versions.
- [Troubleshooting](troubleshooting.md) — common problems.

- [Evaluation Methodology](evaluation-methodology.md) - fixture labels, metric definitions, benchmark commands, and limits.
- [Rule Evaluation Metrics](rule-metrics.md) - per-rule findings, false positives, false negatives, runtime, and JSON/Markdown formats.

## Contributing

- [Contributing](../CONTRIBUTING.md)
- [Contributing through Drips Wave](WAVE.md)
- [Development Setup](development/setup.md)
- [Repository Automation (xtask)](development/xtask.md)
- [Mutation Testing](development/mutation-testing.md)
- [Testing](development/testing.md)
- [Benchmarks](development/benchmarks.md)
- [Writing Rules](contributors/writing-rules.md)
- [Corpus Licensing and Provenance](corpus-provenance.md) - requirements for third-party fixtures.
- [Adding a Language Frontend](contributors/adding-a-frontend.md) - experimental until reviewed.
- [Rule Template](rules/TEMPLATE.md)
- [Contributor Roadmap](contributors/roadmap.md)

## Project

- [Architecture](architecture/overview.md)
- [Workspace layout and module map](architecture/workspace-layout.md)
- [Architecture Decision Records](architecture/adr/README.md)
- [Compatibility](compatibility.md)
- [Releases and Support](releases.md) — cadence, support windows, security targets.
- [Supply-chain verification](supply-chain.md) — checksums, attestations, dependencies.
- [Kubernetes manifests](kubernetes.md) — scheduled and one-off scans.
- [Docker image](docker.md) — build, run, and verify the CLI container.
- [Security Model](security/security-model.md)
- [Threat Model](security/threat-model.md)
- [Project Status](PROJECT_STATUS.md)
- [Issue Backlog](ISSUE_BACKLOG.md)
- [Roadmap](ROADMAP.md)
- [Wave Board](WAVE_BOARD.md)

## Maintainers

- [Release Process](development/release.md)
- [Production Readiness Audit](development/audit.md)
