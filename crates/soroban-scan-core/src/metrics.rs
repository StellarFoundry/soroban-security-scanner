//! Opt-in scan metrics.
//!
//! Metrics describe one scan in a bounded, stable shape suitable for a
//! Prometheus exposition or a JSON side channel. They are deliberately kept out
//! of the deterministic JSON/SARIF reports: durations depend on the machine, and
//! findings must never vary with wall-clock time.
//!
//! Cardinality is bounded because labels only use the finite rule set and the
//! fixed timing status set. Project names, paths, and finding evidence are never
//! used as labels.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::engine::{RuleTimingStatus, ScanOutcome};

/// Stable metric namespace.
pub const NAMESPACE: &str = "soroban_scan";

/// Histogram bucket bounds, in seconds. The final `+Inf` bucket is implicit.
pub const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
];

/// One cumulative histogram bucket.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HistogramBucket {
    /// Inclusive upper bound, in seconds.
    pub le: f64,
    /// Cumulative number of samples at or below `le`.
    pub count: u64,
}

/// A bounded histogram.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Histogram {
    /// Cumulative buckets with finite upper bounds.
    pub buckets: Vec<HistogramBucket>,
    /// Total samples.
    pub count: u64,
    /// Sum of all samples, in seconds.
    pub sum: f64,
}

impl Histogram {
    /// Builds a histogram from sample values in seconds.
    pub fn from_samples(samples: impl IntoIterator<Item = f64>) -> Self {
        let values: Vec<f64> = samples.into_iter().collect();
        let buckets = DURATION_BUCKETS
            .iter()
            .map(|bound| HistogramBucket {
                le: *bound,
                count: values.iter().filter(|value| **value <= *bound).count() as u64,
            })
            .collect();
        Histogram {
            buckets,
            count: values.len() as u64,
            sum: values.iter().sum(),
        }
    }
}

/// Counts for one rule's timing status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RuleStatusCounts {
    /// Rules that completed normally.
    pub completed: u64,
    /// Rules that exceeded their execution budget.
    pub timed_out: u64,
    /// Rules that panicked and were isolated.
    pub panicked: u64,
}

/// Metrics for one rule id.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RuleMetrics {
    /// Stable rule id.
    pub rule_id: String,
    /// Number of executions observed.
    pub runs_total: u64,
    /// How the executions finished.
    pub status: RuleStatusCounts,
    /// Per-execution wall-clock duration.
    pub duration_seconds: Histogram,
}

/// A bounded snapshot of metrics for one scan.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MetricsSnapshot {
    /// Stable metric namespace.
    pub namespace: &'static str,
    /// Number of scans represented (always one per snapshot).
    pub scans_total: u64,
    /// Gate findings in the scan.
    pub findings_total: u64,
    /// Rules executed.
    pub rules_run_total: u64,
    /// Rules skipped by configuration or deprecation.
    pub rules_skipped_total: u64,
    /// Rules that panicked.
    pub rules_failed_total: u64,
    /// End-to-end analysis duration.
    pub scan_duration_seconds: Histogram,
    /// Per-rule metrics, sorted by rule id.
    pub rules: Vec<RuleMetrics>,
}

/// Builds a bounded metrics snapshot from a scan outcome.
pub fn snapshot(outcome: &ScanOutcome) -> MetricsSnapshot {
    let mut by_rule: BTreeMap<&str, (RuleStatusCounts, Vec<f64>)> = BTreeMap::new();
    for timing in &outcome.rule_timings {
        let entry = by_rule.entry(timing.rule_id.as_str()).or_default();
        match timing.status {
            RuleTimingStatus::Completed => entry.0.completed += 1,
            RuleTimingStatus::TimedOut => entry.0.timed_out += 1,
            RuleTimingStatus::Panicked => entry.0.panicked += 1,
        }
        entry.1.push(timing.elapsed_micros as f64 / 1_000_000.0);
    }

    let rules = by_rule
        .into_iter()
        .map(|(rule_id, (status, durations))| {
            let runs_total = status.completed + status.timed_out + status.panicked;
            RuleMetrics {
                rule_id: rule_id.to_string(),
                runs_total,
                status,
                duration_seconds: Histogram::from_samples(durations),
            }
        })
        .collect();

    MetricsSnapshot {
        namespace: NAMESPACE,
        scans_total: 1,
        findings_total: outcome.findings.len() as u64,
        rules_run_total: outcome.stats.rules_run as u64,
        rules_skipped_total: outcome.stats.rules_skipped as u64,
        rules_failed_total: outcome.stats.rules_failed as u64,
        scan_duration_seconds: Histogram::from_samples([
            outcome.stats.elapsed_micros as f64 / 1_000_000.0
        ]),
        rules,
    }
}

impl MetricsSnapshot {
    /// Renders the snapshot in Prometheus text exposition format.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::new();
        out.push_str(&counter(
            "scans_total",
            "Total scans completed.",
            self.scans_total,
        ));
        out.push_str(&counter(
            "findings_total",
            "Findings reported by the gate.",
            self.findings_total,
        ));
        out.push_str(&counter(
            "rules_run_total",
            "Rule executions that completed or failed during the scan.",
            self.rules_run_total,
        ));
        out.push_str(&counter(
            "rules_skipped_total",
            "Rules skipped by configuration or deprecation.",
            self.rules_skipped_total,
        ));
        out.push_str(&counter(
            "rules_failed_total",
            "Rules that panicked and were isolated.",
            self.rules_failed_total,
        ));
        out.push_str(&histogram(
            "scan_duration_seconds",
            "End-to-end analysis duration in seconds.",
            &self.scan_duration_seconds,
            &[],
        ));

        if !self.rules.is_empty() {
            out.push_str(&format!(
                "# HELP {NAMESPACE}_rule_status_total Rule executions by timing status.\n\
                 # TYPE {NAMESPACE}_rule_status_total counter\n"
            ));
        }
        for rule in &self.rules {
            for (status, count) in [
                ("completed", rule.status.completed),
                ("timed_out", rule.status.timed_out),
                ("panicked", rule.status.panicked),
            ] {
                out.push_str(&format!(
                    "{NAMESPACE}_rule_status_total{} {count}\n",
                    label_set(&[("rule_id", rule.rule_id.as_str()), ("status", status)])
                ));
            }
            out.push_str(&histogram(
                "rule_duration_seconds",
                "Per-rule wall-clock duration in seconds.",
                &rule.duration_seconds,
                &[("rule_id", rule.rule_id.as_str())],
            ));
        }
        out
    }
}

fn counter(name: &str, help: &str, value: u64) -> String {
    format!(
        "# HELP {NAMESPACE}_{name} {help}\n\
         # TYPE {NAMESPACE}_{name} counter\n\
         {NAMESPACE}_{name} {value}\n"
    )
}

fn histogram(name: &str, help: &str, histogram: &Histogram, labels: &[(&str, &str)]) -> String {
    let mut out = format!(
        "# HELP {NAMESPACE}_{name} {help}\n\
         # TYPE {NAMESPACE}_{name} histogram\n"
    );
    let base_labels = labels.to_vec();
    for bucket in &histogram.buckets {
        let rendered = if base_labels.is_empty() {
            format!("{{le=\"{}\"}}", format_float(bucket.le))
        } else {
            let mut pairs: Vec<String> = base_labels
                .iter()
                .map(|(key, value)| format!("{key}=\"{value}\""))
                .collect();
            pairs.push(format!("le=\"{}\"", format_float(bucket.le)));
            format!("{{{}}}", pairs.join(","))
        };
        out.push_str(&format!(
            "{NAMESPACE}_{name}_bucket{rendered} {}\n",
            bucket.count
        ));
    }
    let inf_labels = if base_labels.is_empty() {
        "{le=\"+Inf\"}".to_string()
    } else {
        let mut pairs: Vec<String> = base_labels
            .iter()
            .map(|(key, value)| format!("{key}=\"{value}\""))
            .collect();
        pairs.push("le=\"+Inf\"".to_string());
        format!("{{{}}}", pairs.join(","))
    };
    out.push_str(&format!(
        "{NAMESPACE}_{name}_bucket{inf_labels} {}\n",
        histogram.count
    ));
    let label_suffix = if base_labels.is_empty() {
        String::new()
    } else {
        label_set(&base_labels)
    };
    out.push_str(&format!(
        "{NAMESPACE}_{name}_sum{label_suffix} {}\n\
         {NAMESPACE}_{name}_count{label_suffix} {}\n",
        format_float(histogram.sum),
        histogram.count
    ));
    out
}

fn label_set(labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let pairs: Vec<String> = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect();
    format!("{{{}}}", pairs.join(","))
}

fn format_float(value: f64) -> String {
    if value == 0.0 {
        return "0".to_string();
    }
    let rendered = format!("{value}");
    if rendered.contains('e') || rendered.contains('E') {
        format!("{value:.6}")
    } else {
        rendered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::RuleTiming;

    fn outcome(timings: Vec<RuleTiming>, rules_run: usize) -> ScanOutcome {
        let loaded = crate::engine::synthetic_loaded("fn main() {}\n", "src/lib.rs");
        let registry = crate::registry::RuleRegistry::new();
        let mut outcome =
            crate::engine::scan(&loaded, &registry, &crate::config::ScanConfig::default());
        outcome.rule_timings = timings;
        outcome.stats.rules_run = rules_run;
        outcome.stats.rules_skipped = 4;
        outcome.stats.elapsed_micros = 2_500;
        outcome
    }

    #[test]
    fn snapshot_aggregates_rules_and_bounds_labels() {
        let snapshot = snapshot(&outcome(
            vec![
                RuleTiming {
                    rule_id: "SS-001".to_string(),
                    elapsed_micros: 1_000,
                    status: RuleTimingStatus::Completed,
                },
                RuleTiming {
                    rule_id: "SS-001".to_string(),
                    elapsed_micros: 3_000,
                    status: RuleTimingStatus::TimedOut,
                },
                RuleTiming {
                    rule_id: "SS-002".to_string(),
                    elapsed_micros: 2_000,
                    status: RuleTimingStatus::Panicked,
                },
            ],
            3,
        ));
        assert_eq!(snapshot.rules.len(), 2);
        assert_eq!(snapshot.rules[0].rule_id, "SS-001");
        assert_eq!(snapshot.rules[0].runs_total, 2);
        assert_eq!(snapshot.rules[0].status.completed, 1);
        assert_eq!(snapshot.rules[0].status.timed_out, 1);
        assert_eq!(snapshot.scan_duration_seconds.count, 1);
        assert_eq!(snapshot.rules_skipped_total, 4);
    }

    #[test]
    fn prometheus_output_is_stable_and_ends_with_newline() {
        let snapshot = snapshot(&outcome(
            vec![RuleTiming {
                rule_id: "SS-001".to_string(),
                elapsed_micros: 1_000,
                status: RuleTimingStatus::Completed,
            }],
            1,
        ));
        let text = snapshot.to_prometheus();
        assert!(text.ends_with('\n'));
        assert!(text.contains("# TYPE soroban_scan_scans_total counter"));
        assert!(text.contains("soroban_scan_scan_duration_seconds_bucket{le=\"+Inf\"} 1"));
        assert!(text
            .contains("soroban_scan_rule_status_total{rule_id=\"SS-001\",status=\"completed\"} 1"));
        assert!(!text.contains("project"));
        assert_eq!(text, snapshot.to_prometheus());
    }

    #[test]
    fn histogram_buckets_are_cumulative() {
        let histogram = Histogram::from_samples([0.0005, 0.002, 10.0]);
        assert_eq!(histogram.count, 3);
        assert!(histogram.sum > 10.0);
        assert_eq!(histogram.buckets[0].le, 0.001);
        assert_eq!(histogram.buckets[0].count, 1);
        let last = histogram.buckets.last().unwrap();
        assert_eq!(last.count, 3);
    }
}
