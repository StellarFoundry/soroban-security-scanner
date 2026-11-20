# Scan metrics

The scanner can emit bounded metrics for one scan with `--metrics`. Metrics are
opt-in and printed to **stderr** in Prometheus text exposition format, so stdout
stays reserved for the report:

```bash
soroban-scan scan ./contracts --format json --output report.json --metrics 2> metrics.txt
```

Metrics never change findings, ordering, fingerprints, or the exit gate. They are
not part of the deterministic JSON or SARIF report: durations depend on the
machine, and reproducibility requires that report content never vary with
wall-clock time.

## Namespace and cardinality

All metric names use the stable `soroban_scan_` namespace. Labels are restricted
to the finite rule set (`rule_id`) and the fixed timing status
(`completed`, `timed_out`, `panicked`). Project names, file paths, finding
evidence, environment values, and secrets are **never** used as labels, so
cardinality is bounded by the number of registered rules.

## Counters

| Metric | Meaning |
| ------ | ------- |
| `soroban_scan_scans_total` | Scans represented by the snapshot (one per run). |
| `soroban_scan_findings_total` | Findings reported by the gate. |
| `soroban_scan_rules_run_total` | Rules executed. |
| `soroban_scan_rules_skipped_total` | Rules skipped by configuration or deprecation. |
| `soroban_scan_rules_failed_total` | Rules that panicked and were isolated. |
| `soroban_scan_rule_status_total{rule_id,status}` | Executions per rule and timing status. |

## Histograms

| Metric | Meaning |
| ------ | ------- |
| `soroban_scan_scan_duration_seconds` | End-to-end analysis duration. |
| `soroban_scan_rule_duration_seconds{rule_id}` | Per-rule wall-clock duration. |

Histogram buckets are fixed (in seconds):

```
0.001 0.005 0.01 0.05 0.1 0.5 1 5 10 30 60 120 300 +Inf
```

Buckets are cumulative, as required by the Prometheus exposition format. The
snapshot always ends with `count` and `sum` samples.

## Example

```text
# HELP soroban_scan_scans_total Total scans completed.
# TYPE soroban_scan_scans_total counter
soroban_scan_scans_total 1
# HELP soroban_scan_scan_duration_seconds End-to-end analysis duration in seconds.
# TYPE soroban_scan_scan_duration_seconds histogram
soroban_scan_scan_duration_seconds_bucket{le="0.001"} 0
...
soroban_scan_scan_duration_seconds_bucket{le="+Inf"} 1
soroban_scan_scan_duration_seconds_sum 0.042
soroban_scan_scan_duration_seconds_count 1
# HELP soroban_scan_rule_status_total Rule executions by timing status.
# TYPE soroban_scan_rule_status_total counter
soroban_scan_rule_status_total{rule_id="SS-001",status="completed"} 1
soroban_scan_rule_status_total{rule_id="SS-001",status="timed_out"} 0
soroban_scan_rule_status_total{rule_id="SS-001",status="panicked"} 0
```

Operational use of these metrics is covered in the
[operations runbook](operations-runbook.md).
