# CI recipes

Copy-paste snippets for running `soroban-scan` in common CI systems and local
hooks. See the [CLI Reference](cli.md) for every option and the stable exit
code, and [GitHub Integration](github-integration.md) for the full GitHub story.

> Not yet published to crates.io. Until then, install from source:
>
> ```bash
> cargo install --path crates/soroban-scan-cli
> ```

## GitHub Actions

The repository ships a composite Action. The [GitHub Action reference](github-action.md)
documents all inputs, outputs and examples.

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

## GitHub Actions — fail only on new findings

Keep a committed baseline and gate only on regressions:

```yaml
- uses: AyinkxLab/soroban-security-scanner@main
  with:
    path: .
    baseline: .soroban-scan-baseline.json
    fail-on: high
```

Refresh the baseline locally when you intend to accept current findings:

```bash
soroban-scan scan . --write-baseline .soroban-scan-baseline.json --fail-on none
```

## GitHub Actions — changed files only (pull requests)

```yaml
- name: List changed files
  shell: bash
  run: git diff --name-only origin/${{ github.base_ref }}...HEAD > changed.txt
- uses: AyinkxLab/soroban-security-scanner@main
  with:
    path: .
    files-from: changed.txt
    fail-on: none
```

## GitHub Actions — changed projects in a monorepo

`--changed-files` scans whole Cargo projects that a pull request touched,
rather than individual files, so cross-file findings inside a project are kept.
See [Monorepo path filtering](cli.md#monorepo-path-filtering).

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- name: List changed files
  shell: bash
  run: git diff --name-only "origin/${GITHUB_BASE_REF}...HEAD" > changed.txt
- uses: AyinkxLab/soroban-security-scanner@main
  with:
    path: .
    fail-on: high
    args: --changed-files changed.txt --exclude-project 'examples/**'
```

## GitLab CI

```yaml
soroban-scan:
  image: rust:latest
  stage: test
  script:
    - cargo install --path crates/soroban-scan-cli
    - soroban-scan scan . --format json --output report.json --fail-on high
  artifacts:
    when: always
    paths:
      - report.json
```

## pre-commit

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: soroban-scan
        name: soroban-scan
        entry: soroban-scan scan
        language: system
        args: ["--fail-on", "high", "--quiet"]
        pass_filenames: false
```

## Docker

```bash
docker run --rm -v "$PWD:/src" -w /src rust:latest sh -c \
  "cargo build --release -p soroban-scan-cli && ./target/release/soroban-scan scan . --fail-on high"
```

## Makefile

```make
.PHONY: scan
scan:
	cargo run -q -p soroban-scan-cli -- scan . --format json --output report.json --fail-on high
```

## Tips

- Use `--format sarif` with GitHub code scanning; `--format json` for other
  tooling; `--format markdown` to attach a human-readable report to a PR.
- Use `--new-only` together with a baseline to fail on regressions only.
- Use `--incremental` for large repositories to scan only what changed.
- The scanner never needs network access, keys, or wallets, so it is safe to run
  in untrusted/forks. See [Security Model](security/security-model.md).
