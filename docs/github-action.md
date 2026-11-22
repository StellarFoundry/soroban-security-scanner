# GitHub Action

`soroban-scan` ships a composite GitHub Action so you can run Soroban-aware
security analysis directly in your workflow and gate pull requests on new
findings.

- See [GitHub Integration](github-integration.md) for SARIF upload, PR
  annotations, baseline synchronization, and fork safety.
- See the [CLI Reference](cli.md) for the underlying `scan` options.

## Quick start

```yaml
name: Security

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  soroban-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: AyinkxLab/soroban-security-scanner@main
        with:
          path: .
          format: sarif
          output: soroban-scan-results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: soroban-scan-results.sarif
```

> The action is a **composite** action and builds the scanner from source
> (`cargo build --release`), so the first run of a job is slower than a
> pre-built binary. Pin to a released tag (see below) for reproducible runs.

## Inputs

| Input | Description | Required | Default |
| ----- | ----------- | -------- | ------- |
| `path` | Directory or file to scan. | no | `.` |
| `format` | Output format: `terminal`, `json`, `sarif`, `markdown`, or `github`. | no | `sarif` |
| `output` | File to write the report to when the format is machine-readable. | no | `soroban-scan-results.sarif` |
| `fail-on` | Failure threshold: `none`, `info`, `low`, `medium`, `high`, `critical`. | no | `high` |
| `baseline` | Optional baseline file; when set, only **new** findings fail the gate. | no | `""` |
| `files-from` | Optional file containing a newline-separated list of files to scan. | no | `""` |
| `args` | Additional arguments passed to `soroban-scan scan`. | no | `""` |

## Input validation

Before the scan starts, the Action validates its inputs and fails the step with
a clear `::error` annotation instead of letting the scanner fail later with an
opaque message:

- `format` must be one of `terminal`, `json`, `sarif`, `markdown`, or `github`.
- `fail-on` must be one of `none`, `info`, `low`, `medium`, `high`, or
  `critical`.
- `path` must exist.
- `baseline` and `files-from`, when set, must point at readable files.
- `path` and `files-from` are mutually exclusive: set `files-from` with the
  default `path` (`.`) only.
- `output` must not be an existing directory.

Validation never prints secrets or environment contents. Invalid input exits
with code `2` and does not run the scanner.

## Outputs

| Output | Description |
| ------ | ----------- |
| `exit-code` | Scanner exit code (`0` = no failing findings, `1` = failing findings). |

## Examples

### Fail only on new findings (baseline)

```yaml
- uses: AyinkxLab/soroban-security-scanner@main
  with:
    path: .
    baseline: .soroban-scan-baseline.json
    fail-on: high
```

### Scan only the files changed in a pull request

```yaml
- id: changed
  shell: bash
  run: git diff --name-only origin/${{ github.base_ref }}...HEAD > changed.txt
- uses: AyinkxLab/soroban-security-scanner@main
  with:
    path: .
    files-from: changed.txt
    format: markdown
    output: soroban-scan.md
    fail-on: none
```

### Machine-readable JSON for later steps

```yaml
- uses: AyinkxLab/soroban-security-scanner@main
  id: scan
  with:
    path: .
    format: json
    output: report.json
    fail-on: none
- run: echo "scanner exit code was ${{ steps.scan.outputs.exit-code }}"
```

## Build caching

The Action caches its `target/` directory with `actions/cache`. The key includes
the runner OS, the Action ref, and a hash of the Action's `Cargo.lock`, so a new
Action release or a dependency change rebuilds instead of reusing a stale
binary. Cache restore is best-effort: if the cache service is unavailable the
Action builds normally and the workflow does not fail.

Only build outputs are cached. No secrets, tokens, or environment files are
stored in the cache, and fork refs do not reuse trusted-ref caches.

## Permissions

- `contents: read` — required to check out and read the repository.
- `security-events: write` — required only if you upload SARIF to GitHub code
  scanning.
- `pull-requests: write` — required only for the bundled workflow's opt-in
  sticky PR comment.
- `checks: write` — required only for the bundled workflow's opt-in check run
  with inline annotations.

The action makes no network requests beyond building the workflow's own
dependencies; see [GitHub Integration](github-integration.md) for the fork
pull-request safety model, sticky comments, check runs, and baseline refresh
automation.

## Versioning

Pin to a released tag for reproducible runs, or track `main` for the latest
work:

```yaml
- uses: AyinkxLab/soroban-security-scanner@v0.1.0
```

## Marketplace

The action metadata (name, description, author, branding, inputs, outputs) is
declared in [`action.yml`](../action.yml). This page is the canonical usage
reference to link from the GitHub Marketplace listing.
