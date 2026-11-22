# Rule Evaluation Metrics

- **Schema version:** 1
- **Tool:** soroban-scan
- **Corpus:** `fixtures/metrics-sample`
- **Rules covered:** 2
- **Findings:** 5

False positives and false negatives are fixture-level labels from the corpus manifests. Ambiguous fixtures are recorded and excluded from the metric totals, never guessed.

Runtime is measured in microseconds and is the only non-deterministic field.

| Rule | Findings | TP | FP | FN | TN | Positive | Negative | Ambiguous | Runtime (µs) | Status |
| ---- | -------- | -- | -- | -- | -- | -------- | -------- | --------- | ------------ | ------ |
| SS-001 | 2 | 2 | 1 | 0 | 1 | 2 | 2 | 1 | 250 | completed |
| SS-002 | 3 | 1 | 0 | 0 | 2 | 1 | 2 | 0 | 120 | completed |
| **Total** | 5 | 3 | 1 | 0 | 3 | | | 1 | 370 | |
