# Baselines and Incremental Scanning

A baseline records findings you have reviewed and accepted. New scans then report
which findings are **new** versus already known, so CI can gate on regressions
without failing on pre-existing issues.

## Creating a baseline

```bash
soroban-scan scan ./contracts --write-baseline .soroban-scan-baseline.json
```

This writes the current findings' fingerprints to the baseline file and exits
successfully.

## Scanning against a baseline

```bash
soroban-scan scan ./contracts --baseline .soroban-scan-baseline.json
```

The terminal summary reports `new`, `existing`, and `resolved` counts. When a
baseline is supplied, the `--fail-on` gate considers **only new findings**, so
known issues do not fail CI.

Machine-readable reports carry the same comparison. These fields appear only
when `--baseline` is supplied:

- **JSON** adds a top-level `baseline` object with `new`, `existing`, and
  `resolved` counts plus `resolved_findings`. Each entry in `findings` gains a
  `baseline_status` of `new` or `existing`.
- **SARIF** adds `properties.baselineStatus` to each result and the same summary
  under `runs[0].properties.baseline`.

Incremental scans report `resolved` as `0`, because missing findings are not
treated as resolved.

Baseline documents are rejected above 64 MiB before parsing, so an untrusted
file cannot force unbounded memory use.

Use `--new-only` to print only new findings:

```bash
soroban-scan scan ./contracts \
  --baseline .soroban-scan-baseline.json \
  --new-only \
  --format json
```

## Merging baselines

`--baseline` is repeatable, so per-package baselines can be composed for one
scan:

```bash
soroban-scan scan ./contracts \
  --baseline .baseline-api.json \
  --baseline .baseline-worker.toml
```

Files are merged by fingerprint. Entries are sorted by fingerprint and severity,
so duplicate fingerprints keep the same entry regardless of argument order.
Identical fingerprints are de-duplicated.

## Pruning a baseline

When findings are fixed, remove their stale entries explicitly:

```bash
soroban-scan scan ./contracts --prune-baseline .soroban-scan-baseline.json
```

Pruning rewrites the file with only findings present in this scan and prints a
summary (`N removed, M kept`) to stderr. It never runs as a side effect of a
normal scan.

## Stale rule ids

Baseline entries that reference a rule id no longer in the registry produce a
`BASELINE-001` warning diagnostic. The scan still succeeds, so older baselines
remain forward compatible; the warning simply surfaces entries that no longer
apply.

## TOML baselines

JSON is the default format. Write TOML with `--baseline-format toml` or by using a
`.toml` output path:

```bash
soroban-scan scan ./contracts \
  --write-baseline .soroban-scan-baseline.toml \
  --baseline-format toml
```

Reads auto-detect the format, so the same `--baseline` flag accepts both JSON and
TOML. TOML baselines include a `format = "soroban-scan-baseline"` marker.

## Incremental scanning

When you scan only a subset of files (for example, changed files in a pull
request), resolved findings cannot be determined, because files that were not
scanned may still contain them. Pass `--incremental` to disable resolved
reporting:

```bash
soroban-scan scan ./changed/src/lib.rs \
  --baseline .soroban-scan-baseline.json \
  --incremental
```

## CI policy matrix

`--baseline`, `--new-only`, `--incremental`, and `--fail-on` have deliberately
separate jobs:

- `--baseline` changes **what the gate evaluates**: only findings whose
  fingerprints are absent from the baseline ("new" findings).
- `--new-only` changes **what the report prints**: only new findings. It never
  changes which findings the gate evaluates.
- `--incremental` only suppresses the "resolved" count, because a partial scan
  cannot prove that an unscanned file no longer contains a finding.
- `--fail-on` sets the severity threshold; `none` always exits `0`.

The table assumes a baseline was written from the same scan path. "New" means a
finding that is not in the baseline.

| `--baseline` | `--new-only` | `--fail-on` | Findings reported | Gate evaluates | Exit code |
| ------------ | ------------ | ----------- | ----------------- | -------------- | --------- |
| no  | not allowed (usage error) | any | all | — | `2` |
| no  | — | `none` | all | nothing | `0` |
| no  | — | `high` | all | all findings | `1` if any finding is high or critical |
| yes | no | `none` | all (new and known) | nothing | `0` |
| yes | no | `high` | all (new and known) | new findings only | `1` if any **new** finding is high or critical; known high findings exit `0` |
| yes | yes | `none` | new only | nothing | `0` |
| yes | yes | `high` | new only | new findings only | `1` if any **new** finding is high or critical |
| yes | yes/no | `critical` | as above | new findings only | `1` only if a **new** finding is critical |
| yes + `--incremental` | yes/no | as above | as above | new findings only | unchanged; the resolved count is omitted |

Two consequences are easy to get wrong:

- A clean run against a baseline reports known findings (unless `--new-only` is
  set) but still exits `0`, because the gate ignores them.
- `--max-findings` is applied after the gate: truncating the report can never
  hide the finding that caused a non-zero exit.

## Fingerprints

Fingerprints are computed from the **rule id**, the **scan-relative file path**,
and the **normalized evidence**. Line numbers are deliberately excluded, so code
movement does not resurrect known findings or create false "new" findings.
Editing the evidence (for example, changing the flagged call) produces a new
fingerprint, which is intentional.

### Path-independent fingerprints for renamed files

By default (`fingerprint_mode = "include-path"`), moving or renaming a file
changes the relative path input to the fingerprint hash, so findings in the
renamed file appear as new until the baseline is refreshed.

During large workspace refactors or directory reorganizations, you can opt in to
path-independent fingerprints via configuration or CLI:

```toml
# soroban-scan.toml
fingerprint_mode = "path-independent"
```

```bash
soroban-scan scan ./contracts \
  --baseline .soroban-scan-baseline.json \
  --fingerprint-mode path-independent
```

Under `path-independent`, the fingerprint hashes only `rule_id \0 normalized_evidence`
(omitting the relative file path), so findings retain their fingerprints when
files are moved or renamed.

**Collision trade-off:** Two identical code snippets flagged by the same rule in
different files produce the **same** fingerprint under `path-independent`. If
one occurrence is accepted in the baseline, an identical snippet introduced in
another file will also match that baseline entry. Because of this collision
risk, the scanner always emits a `BASELINE-002` warning diagnostic when
`path-independent` mode is active (and notes how many fingerprints matched
findings across multiple files). Both `--write-baseline` and `--baseline` must
use the same `fingerprint_mode`.

## Baseline file format

```json
{
  "version": 1,
  "tool": "soroban-scan",
  "tool_version": "0.1.0",
  "findings": [
    {
      "fingerprint": "…",
      "rule_id": "SS-001",
      "file": "src/lib.rs",
      "severity": "high",
      "title": "State-changing entry point without caller authorization"
    }
  ]
}
```

TOML uses the same fields plus a format marker:

```toml
format = "soroban-scan-baseline"
version = 1
tool = "soroban-scan"
tool_version = "0.1.0"

[[findings]]
fingerprint = "..."
rule_id = "SS-001"
file = "src/lib.rs"
severity = "high"
title = "State-changing entry point without caller authorization"
```

Entries are sorted by fingerprint for deterministic output. Baselines are
treated as untrusted input and validated on load; unsupported versions are
rejected.

## Recommended workflow

1. Add an initial baseline to the repository.
2. In CI, scan with `--baseline` and `--fail-on high`.
3. Fix baseline findings over time and refresh the baseline deliberately:

   ```bash
   soroban-scan scan ./contracts --write-baseline .soroban-scan-baseline.json
   ```

4. Review baseline changes in code review, just like any other file.

## Scheduled refresh

This repository ships
[`.github/workflows/baseline-refresh.yml`](../.github/workflows/baseline-refresh.yml).
It runs weekly and on manual dispatch, regenerates the baseline, and opens (or
updates) a pull request on the `automation/baseline-refresh` branch. It never
pushes to `main` and never auto-merges; the baseline diff is the review artifact.

Defaults:

- Scan path: the repository root, excluding `fixtures/**` and `examples/**`
  because those intentionally contain vulnerable code.
- Baseline: `.soroban-scan-baseline.json`.

Set the repository variables `SOROBAN_SCAN_BASELINE_SCAN_PATH` and
`SOROBAN_SCAN_BASELINE_FILE` to point the workflow at a contract tree and
baseline file of your choosing. See
[GitHub Integration](github-integration.md#scheduled-baseline-refresh).
