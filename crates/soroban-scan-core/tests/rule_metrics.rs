//! Rule evaluation metrics report (#309).
//!
//! The report formats are pinned with golden snapshots. A separate test scans
//! the labeled corpus and proves every shipped rule is covered.

use std::path::PathBuf;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report::metrics::{self, MetricsReport, RuleMetrics};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots")
}

fn assert_golden(name: &str, actual: &str) {
    let path = snapshot_dir().join(name);
    let actual = actual.replace("\r\n", "\n");

    if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
        std::fs::create_dir_all(snapshot_dir()).expect("create snapshot directory");
        std::fs::write(&path, actual.as_bytes())
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden snapshot {}: {error}\n\
             Generate it with UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test rule_metrics",
            path.display()
        )
    });
    let expected = expected.replace("\r\n", "\n");

    assert!(
        expected == actual,
        "{} changed:\n  expected:\n{expected}\n  actual:\n{actual}",
        path.display()
    );
}

fn sample_report() -> MetricsReport {
    MetricsReport::new(
        "fixtures/metrics-sample",
        vec![
            RuleMetrics {
                rule_id: "SS-002".to_string(),
                title: "Example two".to_string(),
                category: "storage".to_string(),
                findings: 3,
                true_positives: 1,
                false_positives: 0,
                false_negatives: 0,
                true_negatives: 2,
                positive_fixtures: 1,
                negative_fixtures: 2,
                ambiguous_fixtures: 0,
                runtime_micros: 120,
                status: "completed".to_string(),
            },
            RuleMetrics {
                rule_id: "SS-001".to_string(),
                title: "Example one".to_string(),
                category: "authorization".to_string(),
                findings: 2,
                true_positives: 2,
                false_positives: 1,
                false_negatives: 0,
                true_negatives: 1,
                positive_fixtures: 2,
                negative_fixtures: 2,
                ambiguous_fixtures: 1,
                runtime_micros: 250,
                status: "completed".to_string(),
            },
        ],
    )
}

#[test]
fn metrics_json_matches_golden_snapshot() {
    let report = sample_report();
    let json = metrics::render_json(&report).expect("metrics JSON must render");
    assert_golden("rule_metrics.json", &json);
}

#[test]
fn metrics_markdown_matches_golden_snapshot() {
    let report = sample_report();
    let markdown = metrics::render_markdown(&report);
    assert_golden("rule_metrics.md", &markdown);
}

#[test]
fn metrics_report_is_deterministic_for_the_same_input() {
    let first = sample_report();
    let second = sample_report();
    assert_eq!(
        metrics::render_json(&first).unwrap(),
        metrics::render_json(&second).unwrap()
    );
    assert_eq!(
        metrics::render_markdown(&first),
        metrics::render_markdown(&second)
    );
}

#[test]
fn every_shipped_rule_is_covered_by_the_corpus_report() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let corpus = repo_root().join("fixtures/corpus");
    let report = metrics::evaluate_corpus(&corpus, "fixtures/corpus", &config, &registry)
        .expect("corpus metrics must evaluate");

    let expected: Vec<&str> = registry.metadata_sorted().iter().map(|meta| meta.id).collect();
    let actual: Vec<&str> = report.rules.iter().map(|rule| rule.rule_id.as_str()).collect();
    assert_eq!(actual, expected);
    assert_eq!(report.totals.rules, registry.len());
    assert!(!report.rules.is_empty());
}
