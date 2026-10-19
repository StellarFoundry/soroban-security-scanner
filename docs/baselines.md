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

Use `--new-only` to print only new findings:

```bash
soroban-scan scan ./contracts \
  --baseline .soroban-scan-baseline.json \
  --new-only \
  --format json
```

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
