# Report retention and artifact naming

Scan reports are build artifacts. Give every report a stable, predictable name,
store it outside the repository, and delete it on a schedule. This page defines
the naming scheme and the recommended retention policy.

## Naming scheme

```text
<project>-<commit7>-<YYYYMMDDTHHMMSSZ>.<extension>
```

- `<project>` is a sanitized project label. ASCII letters, digits, `.`, `_`, and
  `-` are kept; every other character becomes `-`. The label is lowercased,
  trimmed, and capped at 64 characters. It can never contain a path separator,
  shell metacharacter, or absolute path.
- `<commit7>` is the first 7 lowercase hexadecimal characters of the commit
  hash. Full hashes (7-64 hex characters) are accepted; the short form is used
  so names stay readable.
- `<YYYYMMDDTHHMMSSZ>` is the UTC timestamp, compact ISO 8601. UTC is always
  used, never a local timezone.
- `<extension>` follows the report format: `json`, `sarif`, `md`, `html`, `xml`
  (JUnit), or `txt` (terminal/GitHub annotations).

The name is deterministic for the same project, commit, format, and timestamp.
`artifact-name` prints it, and the timestamp defaults to the current UTC time:

```bash
soroban-scan artifact-name --project "Vault Contract" \
  --commit "$(git rev-parse HEAD)" --format json
# vault-contract-abcdef1-20240301T102030Z.json

soroban-scan artifact-name --project vault --commit abcdef12345678 \
  --timestamp 2024-03-01T10:20:30Z --format sarif
# vault-abcdef1-20240301T102030Z.sarif
```

Use the printed name when writing the report:

```bash
name=$(soroban-scan artifact-name --project vault --commit "$GITHUB_SHA")
soroban-scan scan ./contracts --format json --output "artifacts/$name"
```

Names contain no environment values, tokens, user names, or absolute paths. The
project label is caller-supplied: do not pass a secret as the project name.

## Retention guidance

| Artifact | Suggested retention | Why |
| -------- | ------------------- | --- |
| Pull-request scan report | 30 days | Matches typical PR and CI log retention; enough to review a change. |
| Default-branch scan report | 90 days | Lets a regression be traced across a release cycle. |
| Release-attached report | Lifetime of the release | Audit evidence for a shipped contract version. |
| Baseline files | As long as the branch exists | Deleting a baseline makes accepted findings look new. |
| Redacted reports | Same as their source report | Redaction is lossy; keep the unredacted copy under tighter access if policy requires it. |

Operational rules:

- Upload reports to CI artifacts or object storage, not to the repository.
- Keep the most recent successful run per branch; prune older runs on a schedule.
- Treat reports as potentially sensitive even after `--redact`: redaction only
  covers the configured fields and never proves a report is free of secrets.
- Never include tokens, environment dumps, or private keys in a report name or
  report path.
- If a report is attached to a release, record its exact artifact name in the
  release notes so it can be retrieved later.

## Related

- [CLI reference](cli.md) — `artifact-name`, `--output`, and report formats.
- [Policy and reporting](policy.md) — policy schema, precedence, and CI examples.
- [Baselines](baselines.md) — long-lived accepted findings.
