# Security regression corpus

Each rule directory contains fixtures and an `expected.json` manifest.

## Fixtures

- `positive*.rs` (or `.toml` for manifest rules such as SS-015) must trigger the
  directory's rule.
- `negative*.rs` must not trigger it. At least three negatives are required.

## `expected.json`

The manifest lists every fixture file and the **exact** findings it must produce,
including findings from other rules. This makes counts, severities, and
multi-rule fixtures explicit and reviewable.

```json
{
  "schema_version": 1,
  "rule_id": "SS-028",
  "fixtures": [
    {
      "file": "positive.rs",
      "findings": [
        { "rule_id": "SS-013", "count": 1, "severity": "high" },
        { "rule_id": "SS-028", "count": 1, "severity": "high" }
      ]
    },
    { "file": "negative.rs", "findings": [] }
  ]
}
```

- `schema_version` is currently `1`.
- Every fixture file in the directory must have exactly one entry.
- Each finding has a rule id, a positive `count`, and a severity. An optional
  `confidence` field is accepted for forward compatibility, as are unknown
  fields.
- The JSON schema is [`expected.schema.json`](expected.schema.json).

The corpus test (`crates/soroban-scan-core/tests/corpus.rs`) validates the
manifests, scans every fixture, and fails on any mismatch.

## Regenerating manifests

Only regenerate after an intentional detector change, and review the diff:

```bash
UPDATE_EXPECTATIONS=1 cargo test -p soroban-scan-core --test corpus
```

On PowerShell:

```powershell
$env:UPDATE_EXPECTATIONS="1"; cargo test -p soroban-scan-core --test corpus
```
