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

## Fingerprint strategies

A finding fingerprint determines whether a later scan considers the finding
**new** or **existing**. The strategy is configurable with
`--fingerprint-strategy` or the `fingerprint` configuration field.

| Strategy | Hashes | Use when |
| -------- | ------ | -------- |
| `rule-file-evidence` (default) | rule id, file path, evidence | You want the historical behavior. Stable across unrelated line shifts. |
| `rule-file-line-evidence` | rule id, file path, line, evidence | You need line-sensitive matching. |
| `rule-file-line-column-evidence` | rule id, file path, line, column, evidence | You need exact position matching. |
| `path-independent` | rule id, evidence | Refactors rename or move files and you want findings to keep matching. |

The default is byte-for-byte the historical fingerprint, so **existing baselines
remain valid** until you deliberately change the strategy.

> [!WARNING]
> Changing the fingerprint strategy invalidates existing baselines: findings that
> match under one strategy may appear new under another. Regenerate the baseline
> (`--write-baseline`) in the same change and review the diff before merging.

`path-independent` deliberately omits the file path. That makes a renamed or
moved file keep its baseline status, but it also increases the chance of
collisions: two structurally identical findings in different files produce the
same fingerprint. Review `path-independent` baselines for duplicate findings, and
prefer the default when file paths are stable.

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

## Baseline synchronization (`baseline push` and `baseline pull`)

Baseline sync enables CI pipelines and distributed developer environments to share
and persist baselines across workflow runs without committing baseline files directly
to git on every change.

### The baseline envelope

When pushed, a baseline payload is wrapped inside a deterministic metadata envelope:

```json
{
  "version": 1,
  "registry_fingerprint": "a4f8b2c1...",
  "revision": 1,
  "content_hash": "e3b0c442...",
  "payload": "{\"version\":1,\"findings\":[...]}"
}
```

Envelope fields:
- `version`: Envelope schema version (`1`).
- `registry_fingerprint`: SHA-256 digest over the active engine rule IDs and versions,
  sorted alphabetically. Guarantees that a baseline pulled from storage was produced by
  a compatible rule set.
- `revision`: Monotonically increasing revision counter (e.g. GitHub run attempt or build counter).
- `content_hash`: SHA-256 digest over the raw payload string.
- `payload`: The serialized baseline document.

### Verification order (fail-closed)

When pulling an artifact, verification executes in a strict order and fails closed:
1. **Size check**: The artifact cannot exceed 64 MiB (`MAX_ENVELOPE_BYTES`). Rejected before parsing.
2. **Envelope schema**: JSON deserialization of the envelope.
3. **Envelope version**: Rejects schema versions other than `1`.
4. **Registry fingerprint**: Ensures the envelope's rule fingerprint matches the running binary's active rule registry.
5. **Content hash**: Recalculates SHA-256 over `payload` and compares with `content_hash`.
6. **Payload deserialization**: Verifies that the payload parses into a valid baseline document.

If any check fails, the command terminates with exit code `3` and an actionable error. A mismatched baseline is never silently used as an empty baseline.

### Key naming and validation

Baseline keys are supplied via `--key` and must conform to:
- Allowed characters: `[A-Za-z0-9._-]`
- Length: 1 to 128 characters
- No directory separators (`/`, `\`) and no relative directory traversal segments (`..`)

Invalid keys are rejected with exit code `2` before any file or storage I/O occurs.

### Overwrite protection

Before pushing an updated baseline, `baseline push` fetches any existing baseline under that key:
- If no baseline exists: the push proceeds.
- If local `revision > remote revision`: the push proceeds.
- If remote `revision > local revision`: the push is refused with exit code `3` unless `--force` is provided.
- If `local revision == remote revision` but content hashes differ (diverged): the push is refused with exit code `3` unless `--force` is provided.

In non-interactive CI, `--force` should be omitted so concurrent or out-of-order runs cannot overwrite newer state.

### Missing baselines on pull

When pulling a key that does not yet exist in the store (for example, on the first CI run of a new branch or repository), `soroban-scan baseline pull` prints:

```text
notice: no baseline found for key '<KEY>'; continuing without baseline
```

and exits `0` without creating a file. Downstream scan commands without `--baseline` will evaluate all findings as new, maintaining seamless onboarding.

### GitHub Actions integration

> [!NOTE]
> GitHub's REST API allows listing and downloading Actions artifacts, but artifact uploads
> are not supported over REST—they require runner actions like `actions/upload-artifact` or
> `actions/cache`. `soroban-scan baseline` uses a directory-backed store (`--store-dir`)
> designed to interface directly with GitHub Actions primitives.

#### Example: Moving baselines via `actions/cache`

```yaml
name: Security Scan with Cached Baseline

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Restore the latest baseline directory for the default branch
      - name: Restore baseline store
        uses: actions/cache/restore@v4
        with:
          path: .soroban-scan-store
          key: soroban-scan-baseline-main
          restore-keys: |
            soroban-scan-baseline-

      # Pull baseline from local store (exits 0 with notice if absent)
      - name: Pull baseline
        run: |
          soroban-scan baseline pull \
            --key soroban-scan-baseline-main \
            --output current-baseline.json \
            --store-dir .soroban-scan-store

      # Scan against the pulled baseline if present
      - name: Scan contracts
        run: |
          if [ -f current-baseline.json ]; then
            soroban-scan scan ./contracts --baseline current-baseline.json --fail-on high
          else
            soroban-scan scan ./contracts --fail-on high
          fi

      # On main branch: update and push the new baseline into the store
      - name: Refresh and push baseline
        if: github.ref == 'refs/heads/main'
        run: |
          soroban-scan scan ./contracts --write-baseline new-baseline.json --fail-on none
          soroban-scan baseline push \
            --key soroban-scan-baseline-main \
            --file new-baseline.json \
            --store-dir .soroban-scan-store \
            --revision ${{ github.run_number }}

      # Save updated baseline store to GitHub Actions cache
      - name: Save baseline store
        if: github.ref == 'refs/heads/main'
        uses: actions/cache/save@v4
        with:
          path: .soroban-scan-store
          key: soroban-scan-baseline-main-${{ github.run_number }}
```

### Security & Threat Model

- **Consistency vs Authenticity**: The envelope verification checks provide data integrity,
  schema compatibility, and rule-set consistency. They do **not** provide cryptographic
  authenticity or origin proof. Any party with write access to the CI artifact storage
  can push a baseline envelope that suppresses findings.
- **Trusted Writers**: Artifact stores must only be updated by trusted workflows (such as
  protected runs on the default branch `main`). Pull-request runs should only pull baselines
  and should not be permitted to overwrite store keys.
- **Secret Redaction**: Error messages and logs automatically redact GitHub tokens (`GITHUB_TOKEN`,
  `GH_TOKEN`) and bearer token formats to prevent credential leakage in CI logs.

