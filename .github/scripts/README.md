# GitHub integration scripts

These scripts are **CI-only** helpers used by the workflows in
`.github/workflows/`. Unlike the offline tooling in `tools/`, they call the
GitHub CLI (`gh api`) and therefore need network access and a workflow token.

| Script | Purpose | Required token permission |
| ------ | ------- | ------------------------- |
| `pr_comment.py` | Create or update the single sticky pull-request comment. | `pull-requests: write` |
| `check_run.py` | Create a check run with inline annotations from a JSON report. | `checks: write` |

Both scripts never print or persist the token; `gh` reads it from `GH_TOKEN`.
They support `--dry-run` for local inspection.

`github_api.py` is the shared `gh api` wrapper. It reads an installation with
`get_installation` when a GitHub App caller needs the installation id (the
workflows use `GITHUB_TOKEN` and do not). Read-only requests retry transient
failures (HTTP 429/5xx, timeouts, connection resets) up to three attempts.
Mutating requests are never retried, because GitHub does not deduplicate
comment or check-run creation.

Tests use a deterministic in-memory mock instead of `gh`; they need no token
and make no network calls. Run them with:

```bash
python -m unittest discover -s tests/github -v
```
