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
- [Baselines](baselines.md) - track new vs. known findings.
- [Policy and Reporting](policy.md) - policy schema, precedence, waivers, and report formats.
- [Report Retention](retention.md) - deterministic artifact names and retention guidance.
- [GitHub Integration](github-integration.md) — Action, SARIF, PR scanning.
- [GitHub Action](github-action.md) — inputs, outputs, and usage examples.
- [CI Recipes](ci-recipes.md) — copy-paste snippets for common CI systems and hooks.
- [Observatory Integration](integration/observatory.md) — the stable, versioned report contract.
- [Editor integration (LSP spike)](integration/editor-integration.md) — diagnostics-in-editor scope and plan.
- [Optional AI Assistance](ai.md) — off by default, never authoritative.
- [AI privacy and data flow](ai-privacy.md) — exactly what can leave the machine.
- [FAQ](faq.md) — common questions about false positives, CI gating, and versions.
- [Troubleshooting](troubleshooting.md) — common problems.

## Contributing

- [Contributing](../CONTRIBUTING.md)
- [Contributing through Drips Wave](WAVE.md)
- [Development Setup](development/setup.md)
- [Repository Automation (xtask)](development/xtask.md)
- [Mutation Testing](development/mutation-testing.md)
- [Testing](development/testing.md)
- [Benchmarks](development/benchmarks.md)
- [Writing Rules](contributors/writing-rules.md)
- [Rule Template](rules/TEMPLATE.md)
- [Contributor Roadmap](contributors/roadmap.md)

## Project

- [Architecture](architecture/overview.md)
- [Workspace layout and module map](architecture/workspace-layout.md)
- [Architecture Decision Records](architecture/adr/README.md)
- [Compatibility](compatibility.md)
- [Security Model](security/security-model.md)
- [Threat Model](security/threat-model.md)
- [Project Status](PROJECT_STATUS.md)
- [Issue Backlog](ISSUE_BACKLOG.md)
- [Roadmap](ROADMAP.md)
- [Wave Board](WAVE_BOARD.md)

## Maintainers

- [Release Process](development/release.md)
- [Production Readiness Audit](development/audit.md)
