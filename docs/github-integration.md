# GitHub Integration

The scanner integrates with GitHub through a composite Action, a SARIF workflow,
and changed-file pull-request analysis. All integrations are read-only by default
and never post or create anything unless explicitly enabled.

## Permissions summary

| Capability | Permission | Notes |
| ---------- | ---------- | ----- |
| Read repository contents | `contents: read` | Always required. |
| Upload SARIF | `security-events: write` | Required for code scanning. Not available to fork PRs. |
| Comment on a PR | `pull-requests: write` | Only when opt-in commenting is enabled. |
| Create a check run | `checks: write` | Only when opt-in check runs are enabled. Not available to fork PRs. |
| Create issues | `issues: write` | Only for explicitly enabled issue creation; not enabled by default. |

The scanner itself needs no token and makes no network requests.

## Using the action

```yaml
name: Security
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AyinkxLab/soroban-security-scanner@main
        with:
          path: ./contracts
          format: sarif
          output: results.sarif
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

The action builds the scanner from source. Use `if: always()` on the upload step
so results are still published when the gate fails.

### Action inputs

| Input | Default | Description |
| ----- | ------- | ----------- |
| `path` | `.` | Directory or file to scan. |
| `format` | `sarif` | `terminal`, `json`, `sarif`, or `markdown`. |
| `output` | `soroban-scan-results.sarif` | Report path. |
| `fail-on` | `high` | Failure threshold (`none` disables gating). |
| `baseline` | *(empty)* | Baseline file; gate applies to new findings only. |
| `files-from` | *(empty)* | File listing files to scan (changed-file analysis). |
| `args` | *(empty)* | Extra `scan` arguments. |

## Reusable workflow

[`reusable-scan.yml`](../.github/workflows/reusable-scan.yml) packages the same
scan as the composite action in a `workflow_call` workflow. Consumers do not
need to copy YAML or build the scanner themselves.

```yaml
name: Security
on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    permissions:
      contents: read
    uses: StellarFoundry/soroban-security-scanner/.github/workflows/reusable-scan.yml@main
    with:
      path: contracts
      format: sarif
      output: soroban-scan-results.sarif
      fail-on: high
```

The workflow checks out the caller repository, builds the scanner from source,
runs the scan from the caller repository root (so paths and configuration
discovery behave like the action), and uploads the report as the
`soroban-scan-report` artifact.

### Workflow inputs

| Input | Default | Description |
| ----- | ------- | ----------- |
| `path` | `.` | Directory or file to scan. |
| `format` | `sarif` | `terminal`, `json`, `sarif`, or `markdown`. |
| `output` | `soroban-scan-results.sarif` | Report path; set to `""` to skip file output. |
| `fail-on` | `high` | Failure threshold (`none` disables gating). |
| `baseline` | *(empty)* | Baseline file; gate applies to new findings only. |
| `files-from` | *(empty)* | File listing files to scan (changed-file analysis). |
| `args` | *(empty)* | Extra `scan` arguments. |
| `scanner-repository` | `StellarFoundry/soroban-security-scanner` | Scanner source repository. |
| `scanner-ref` | `main` | Scanner source ref; override to test unreleased changes. |

Outputs are `exit-code` (the scanner exit code) and `report` (the report path
when one was written).

### Permissions

The reusable workflow requests only `contents: read` and never requires a
secret. It does **not** upload SARIF itself, so callers that want code-scanning
alerts should keep the scan and the upload in separate jobs and grant
`security-events: write` only to the upload job:

```yaml
jobs:
  scan:
    permissions:
      contents: read
    uses: StellarFoundry/soroban-security-scanner/.github/workflows/reusable-scan.yml@main
    with:
      path: contracts
      format: sarif

  upload:
    needs: scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: soroban-scan-report
          path: results
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results/soroban-scan-results.sarif
```

Fork pull requests cannot receive `security-events: write`; guard the upload job
with the same fork check used by the bundled PR workflow.

This repository exercises the reusable workflow from
[`security-scan.yml`](../.github/workflows/security-scan.yml) on every push and
pull request, using the current commit as the scanner source.

### Main-branch scanning

[`main-scan.yml`](../.github/workflows/main-scan.yml) runs on every push to
`main` and on manual dispatch. It scans the repository code (excluding the
intentionally vulnerable `fixtures/**` and `examples/**`), compares against the
committed `.soroban-scan-baseline.json`, and uploads SARIF with the
`soroban-scan-main` category. The `--fail-on high` gate makes post-merge drift
visible instead of waiting for the next pull request.

Baseline updates stay reviewable: the scheduled
[`baseline-refresh.yml`](../.github/workflows/baseline-refresh.yml) opens a pull
request on `automation/baseline-refresh` rather than pushing to `main`. The main
scan never rewrites the baseline and never force-pushes.

## SARIF and code scanning

Upload SARIF 2.1.0 to surface findings in the repository's **Security → Code
scanning** tab and as inline annotations on pull requests. Fork pull requests do
not receive `security-events: write`, so upload steps should be guarded:

```yaml
if: github.event.pull_request.head.repo.full_name == github.repository
```

The bundled [`.github/workflows/pr-scan.yml`](../.github/workflows/pr-scan.yml)
does this.

### Private repositories

Code scanning on private and internal repositories requires **GitHub Code
Security** to be enabled for the repository (public repositories enable code
scanning automatically on the first upload). If it is not enabled, the upload
fails with:

```text
GitHub Code Security or GitHub Advanced Security must be enabled for this
repository to use code scanning
```

Enable it under **Settings → Code security and analysis → Code scanning**, or
ask an organization owner to enable GitHub Code Security for the repository. On
GitHub Enterprise Server, code scanning also requires a GitHub Advanced Security
license.

The upload job needs one extra permission on private repositories:
`actions: read`. Grant it alongside `contents: read` and
`security-events: write`:

```yaml
permissions:
  actions: read
  contents: read
  security-events: write
```

Also confirm that the repository or organization Actions policy allows the
`github/codeql-action` action, which provides `upload-sarif`. Uploads from fork
pull requests are still rejected, regardless of repository visibility.

See GitHub's documentation for
[uploading a SARIF file](https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github)
and
[managing security and analysis settings](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-security-and-analysis-settings-for-your-repository).

## Changed-file (pull request) analysis

`--files-from` scans only the files listed in a file, which is how the PR
workflow limits work to changed Rust files:

```bash
git diff -M --name-only --diff-filter=ACMR origin/main...HEAD -- '*.rs' > changed.txt
soroban-scan scan . --files-from changed.txt --baseline .baseline.json --incremental
```

Use `--incremental` so the scanner does not report resolved findings, which
cannot be determined from a partial scan. `--files-from` rejects `..` entries
that would escape the scan root.

The PR workflow applies four edge-case guards before scanning:

- `--diff-filter=ACMR` excludes deleted paths, and `-M` keeps only the
  destination of a rename. A pure rename therefore scans the new path once.
- Every listed path must still exist as a regular file. A stale path from a
  force-push or a path that disappeared between checkout and diff is skipped.
- Symlinks and submodule index entries (`git ls-files -s` mode `160000`) are
  skipped, so a submodule path is never treated as Rust source.
- Only paths ending in `.rs` are written to `changed.txt`; duplicates are
  avoided by the diff itself.

Manual verification (documented for reviewers):

```bash
# 1. Rename a tracked Rust file and confirm only the new path is listed.
git mv crates/soroban-scan-core/src/rules/unsafe_code.rs /tmp/renamed.rs
git mv /tmp/renamed.rs crates/soroban-scan-core/src/rules/unsafe_code_renamed.rs
git commit -m "temp: rename"
git diff -M --name-only --diff-filter=ACMR origin/main...HEAD -- '*.rs'
# Expect .../unsafe_code_renamed.rs and not .../unsafe_code.rs.

# 2. Delete a tracked Rust file and confirm it is absent from changed.txt.
git rm crates/soroban-scan-core/src/rules/unsafe_code_renamed.rs
git commit -m "temp: delete"
git diff -M --name-only --diff-filter=ACMR origin/main~1...HEAD -- '*.rs'
# Expect no deleted path in the output.
```

Both cases leave `changed.txt` deterministic: deletes never reach the scanner,
and renames never scan the old, missing path.

## PR annotations

Use `--format github` to emit workflow annotations without a `jq` post-processing
step. `pr-scan.yml` runs it with `--min-severity high`, so high and critical
findings become `::error` annotations independent of code scanning:

```bash
soroban-scan scan . --files-from changed.txt \
  --format github --min-severity high --fail-on none
```

The renderer emits one annotation per finding and escapes `%`, CR, LF, `:`, and
`,` in user-controlled values, so scanned source paths, titles, and evidence
cannot inject additional workflow commands:

```text
::error file=src/lib.rs,line=42,title=SS-001%3A State-changing entry point without caller authorization::SS-001: State-changing entry point without caller authorization — ...
```

Workflow commands are simple but unstructured. The opt-in check run described
below adds severity levels, remediation details, and an explicit pass/fail
conclusion through the Checks API.

## Opt-in PR comments

Commenting is **disabled by default** to avoid noise. Enable it by setting the
repository variable `SOROBAN_SCAN_PR_COMMENT` to `true`:

```bash
gh variable set SOROBAN_SCAN_PR_COMMENT --body true
```

When enabled, the workflow maintains **one sticky summary comment per pull
request**. Each run looks for a hidden marker
(`<!-- soroban-scan:sticky-comment -->`) in existing comments, edits the first
match, and creates a comment only when none exists. Duplicate marked comments
left by older runs are deleted, so a PR never accumulates scanner comments as it
is pushed to. It never runs for fork pull requests.

The logic lives in
[`.github/scripts/pr_comment.py`](../.github/scripts/pr_comment.py) and uses
`gh api` with pagination. The script never prints or persists the workflow
token.

## Check runs with inline annotations

The Checks API can attach structured annotations (with `failure`, `warning`, and
`notice` levels) and a pass/fail conclusion to a commit. This is optional and
disabled by default. Enable it with the repository variable
`SOROBAN_SCAN_CHECK_RUN`:

```bash
gh variable set SOROBAN_SCAN_CHECK_RUN --body true
```

The workflow then runs
[`.github/scripts/check_run.py`](../.github/scripts/check_run.py), which:

- Reads the `--format json` report produced by the changed-file scan.
- Creates a completed check run named **Soroban Security Scan** at the pull
  request's head SHA.
- Maps `critical` and `high` findings to `failure` annotations, `medium` to
  `warning`, and `low`/`info` to `notice`.
- Sets the check conclusion to `failure` when a finding meets the configured
  threshold (default `high`), and `success` otherwise.
- Caps annotations at GitHub's limit of 50 per request and notes any omitted
  findings in the summary; the JSON report remains complete.

Override the threshold with the `SOROBAN_SCAN_CHECK_RUN_FAIL_ON` repository
variable (`none`, `info`, `low`, `medium`, `high`, or `critical`).

## Policy status gate check

The check run above recomputes a severity threshold from the report. The
**policy status gate** instead publishes the scanner's own policy decision, so
the check reflects `--policy-file`, suppressions, waivers, and baselines
exactly. It is also opt-in and disabled by default:

```bash
gh variable set SOROBAN_SCAN_STATUS_GATE --body true
# Optional: gate on a policy document instead of the default `high` threshold.
gh variable set SOROBAN_SCAN_POLICY_FILE --body .github/soroban-scan-policy.toml
```

The bundled PR workflow then:

1. Scans the changed files and uploads the JSON report as the
   `soroban-scan-gate-report` artifact (kept for 30 days).
2. Re-runs the deterministic scan with `--status-gate gate.json` and
   `--report-url` set to that artifact, so the summary links to the report.
3. Runs `check_run.py --gate gate.json`, which creates a completed check run
   named **Soroban Security Gate** with the gate's conclusion, title, and
   summary, plus the usual inline annotations.

| Conclusion | Meaning |
| ---------- | ------- |
| `success` | The policy is enforced and no gated finding meets its threshold. |
| `failure` | A gated finding meets the threshold, or a waiver has expired. |
| `neutral` | The policy disables the gate (`fail_on = "none"`), or nothing was scanned. |

Suppressed, waived, and baseline-accepted findings are counted in the summary
but never fail the check. Make **Soroban Security Gate** a required status
check in branch protection to block merges on a policy failure. The same
fork-PR guard and `checks: write` permission apply as for check runs. See
[Policy status gate](cli.md#policy-status-gate) for the record format.

## API retries and offline tests

The shared `gh api` wrapper retries **read-only** requests up to three times on
HTTP 429, HTTP 5xx, timeouts, and connection resets. It never retries comment
creation, comment updates, deletes, or check-run creation: GitHub does not
deduplicate those requests, so a retry could post twice. A permanent failure is
returned on the first attempt. No delay or retry policy is configurable, which
keeps workflow behaviour predictable.

The scripts are tested against a deterministic in-memory mock of `gh api`. The
suite asserts installation lookup, check-run and comment request paths and
bodies, pagination, malformed responses, and retry versus no-retry behaviour.
It uses no credentials and performs no network access:

```bash
python -m unittest discover -s tests/github -v
```

Required permissions:

```yaml
permissions:
  contents: read
  checks: write
```

Fork pull requests receive a read-only token and cannot create checks. The
workflow guards the step with
`github.event.pull_request.head.repo.full_name == github.repository`, so fork
PRs are skipped entirely.

## Baseline synchronization

Store a baseline in the repository and pass it to the action:

```yaml
- uses: AyinkxLab/soroban-security-scanner@main
  with:
    baseline: .soroban-scan-baseline.json
```

Refresh it deliberately with `soroban-scan scan . --write-baseline …` and review
the change in code review, just like any other file. See
[`baselines.md`](baselines.md).

### Scheduled baseline refresh

[`baseline-refresh.yml`](../.github/workflows/baseline-refresh.yml) runs weekly
(and on manual dispatch), regenerates the committed baseline, and opens or
updates a pull request on the `automation/baseline-refresh` branch. It never
pushes to `main` and never auto-merges, so a maintainer must review the baseline
diff before it is accepted.

By default it scans the repository root while excluding `fixtures/**` and
`examples/**` (which intentionally contain vulnerable code) and writes
`.soroban-scan-baseline.json`. Override the target with repository variables:

```bash
gh variable set SOROBAN_SCAN_BASELINE_SCAN_PATH --body ./contracts
gh variable set SOROBAN_SCAN_BASELINE_FILE --body .soroban-scan-baseline.json
```

The workflow uses `GITHUB_TOKEN`, so pull requests it creates do not trigger
other workflows. Configure a separate automation token only if your repository
requires those checks to run on automation PRs.

## Issue creation (opt-in)

The scanner never creates issues automatically. If you want to file issues for
confirmed findings, do it explicitly in your own workflow, gated behind a manual
trigger or a repository variable, for example:

```yaml
- name: File issues for confirmed findings
  if: vars.SOROBAN_SCAN_CREATE_ISSUES == 'true'
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    jq -r '.findings[] | select(.severity == "critical") | "\(.rule_id)\t\(.location.file):\(.location.line)\t\(.title)"' results.json |
    while IFS=$'\t' read -r rule loc title; do
      gh issue create --title "[${rule}] ${title}" --body "Location: \`${loc}\`"
    done
```

Guidance:

- Never enable issue creation for untrusted (fork) pull requests.
- Deduplicate before creating issues; the same fingerprint recurs across runs.
- Keep it manual or scheduled, not on every push.

## Fork pull-request safety

- Fork PRs run with a read-only `GITHUB_TOKEN` and no access to repository
  secrets.
- Never `checkout` untrusted code and run privileged steps together.
- The scanner never executes, builds, or modifies the code it scans, which makes
  it safe to run on fork PR content.
- Guard SARIF upload and commenting with the fork check shown above.

## Security guarantees

- No network access by the scanner.
- No secrets are read or emitted.
- No repository content is modified.
- No issues, comments, or check runs are created unless explicitly enabled.
- Sticky comments and check runs never run for fork pull requests, and never
  include secrets.

## Verifying the integrations

Use a throwaway pull request in a fork or test repository:

1. **Sticky comment:** enable `SOROBAN_SCAN_PR_COMMENT`, push once, then push
   again. The comment ID and update timestamp change, but the number of marked
   comments stays at one.
2. **Check run:** enable `SOROBAN_SCAN_CHECK_RUN`. Confirm the **Soroban
   Security Scan** check appears on the pull request head SHA with structured
   annotations and a conclusion that matches the findings. Pushing a fix should
   produce a later check run with a `success` conclusion.
3. **Baseline refresh:** run the `Baseline Refresh` workflow with
   `workflow_dispatch`. Confirm it opens or updates a pull request on
   `automation/baseline-refresh`; running it again with no baseline drift should
   leave the branch unchanged.

Fork pull requests should show none of these side effects.

## GitHub Enterprise Server

The PR comment and check-run helpers
([`github_api.py`](../.github/scripts/github_api.py)) talk to github.com by
default. To use GitHub Enterprise Server (or GHE.com), set the opt-in
environment variable `SOROBAN_SCAN_GITHUB_API_URL` on the step that runs them:

```yaml
- name: Comment on the pull request
  env:
    GH_ENTERPRISE_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    SOROBAN_SCAN_GITHUB_API_URL: https://github.example.com/api/v3
  run: python3 .github/scripts/pr_comment.py --body-file comment.md
```

The scanner itself still makes no network requests; this only affects those
two helper scripts.

### Accepted values

| Value | Meaning |
| ----- | ------- |
| `https://github.example.com/api/v3` | GitHub Enterprise Server |
| `https://api.<tenant>.ghe.com` | GHE.com (data residency) |
| `https://api.github.com` | github.com (same as leaving it unset) |
| `http://localhost:8080`, `http://127.0.0.1:9000`, `http://[::1]:9000` | Loopback only, for local mock servers and tests |

The value is validated before any request is made. It is rejected when it:

- uses `http` for a non-loopback host, or any scheme other than `https`/`http`;
- embeds credentials (`user:password@`), a query string or a fragment;
- has a path other than empty or `/api/v3`;
- contains whitespace or control characters, or is longer than 2048 characters.

Rejection messages never repeat the value, so a secret pasted into the URL by
mistake is not written to the job log. Never put a token in the URL.

### Authentication, TLS and proxies

- **Token:** the helpers never read, print or store a token; `gh` does. For a
  GitHub Enterprise Server host, provide it as `GH_ENTERPRISE_TOKEN` (use
  `GH_TOKEN` for github.com).
- **TLS:** certificates are always verified by `gh`. There is no option to
  disable verification. For a private CA, install the CA in the runner's trust
  store (or point `SSL_CERT_FILE` / `SSL_CERT_DIR` at it).
- **Proxy:** `gh` honors `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY`. Set them
  in the step `env` when the runner reaches your server through a proxy.
- **Loopback `http`:** accepted by validation for local mock servers. Transport
  is performed by `gh`, so it works only where your `gh` version supports a
  plain-HTTP host.
- **Check run link:** the details link already uses `GITHUB_SERVER_URL`, which
  GitHub Enterprise Server sets automatically.
