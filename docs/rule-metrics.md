# Rule Evaluation Metrics

The rule evaluation report summarizes rule quality over the labeled regression
corpus. It has one row for every shipped rule, enumerated from the rule registry,
so a rule cannot silently disappear from the report.

## What is measured

- **Findings:** the number of findings each rule produced across the corpus,
  including findings a rule reports in another rule's fixture directory.
- **False positives and false negatives:** fixture-level labels from each
  rule's `fixtures/corpus/<ID>/expected.json` manifest. A positive fixture that
  does not trigger its rule is a false negative. A negative fixture that does
  trigger its rule is a false positive.
- **True positives and true negatives:** the corresponding correct outcomes at
  fixture level.
- **Runtime:** measured elapsed microseconds per rule over the same fixture
  scans. Runtime is the only non-deterministic field in the report.
- **Ambiguous fixtures:** fixtures whose name and manifest do not agree on a
  positive or negative label. They are counted and excluded from the metric
  totals rather than guessed.

See [Evaluation Methodology](evaluation-methodology.md) for why fixture-level
metrics are regression evidence, not a claim of production precision or recall.

## Formats

The report is available as deterministic JSON and Markdown. Rules are sorted by
id, fields are emitted in a fixed order, and totals are computed from the rows.
The report contains only rule ids, catalog metadata already published in the rule
documentation, counts, and durations. It never includes source text, finding
evidence, absolute paths, environment data, or user identifiers.

JSON:

```json
{
  "schema_version": "1",
  "tool": "soroban-scan",
  "corpus": "fixtures/corpus",
  "rules": [
    {
      "rule_id": "SS-001",
      "title": "Missing authorization",
      "category": "authorization",
      "findings": 2,
      "true_positives": 1,
      "false_positives": 0,
      "false_negatives": 0,
      "true_negatives": 3,
      "positive_fixtures": 1,
      "negative_fixtures": 3,
      "ambiguous_fixtures": 0,
      "runtime_micros": 120,
      "status": "completed"
    }
  ],
  "totals": {
    "rules": 1,
    "findings": 2,
    "true_positives": 1,
    "false_positives": 0,
    "false_negatives": 0,
    "true_negatives": 3,
    "ambiguous_fixtures": 0,
    "runtime_micros": 120
  }
}
```

Markdown uses the same rows in a table with columns for findings, TP, FP, FN, TN,
fixture counts, ambiguous fixtures, runtime, and execution status. The
`status` field is `completed`, `timed_out`, `panicked`, or `not_run`.

## Snapshot

`crates/soroban-scan-core/tests/snapshots/rule_metrics.json` and
`rule_metrics.md` pin the formats with fixed metric values. Regenerate them only
after an intentional format change:

```bash
UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test rule_metrics
```

On PowerShell:

```powershell
$env:UPDATE_SNAPSHOTS="1"; cargo test -p soroban-scan-core --test rule_metrics
```

The corpus test in the same file also asserts that every registered rule appears
in the evaluated report.
