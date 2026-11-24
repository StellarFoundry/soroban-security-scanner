//! Per-rule execution statistics (#305).
//!
//! Entries exist only for rules that ran, carry a coarse deterministic
//! duration, and record a skip reason when a rule's output was discarded.

use std::time::Duration;

use soroban_scan_core::category::Category;
use soroban_scan_core::confidence::Confidence;
use soroban_scan_core::config::{RulesConfig, ScanConfig};
use soroban_scan_core::context::AnalysisContext;
use soroban_scan_core::engine;
use soroban_scan_core::finding::Finding;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report;
use soroban_scan_core::rule::{Rule, RuleMetadata};
use soroban_scan_core::severity::Severity;

const SOURCE: &str = include_str!("../../../fixtures/exploitability/reachable.rs");

fn config() -> ScanConfig {
    ScanConfig::default()
}

fn registry() -> RuleRegistry {
    RuleRegistry::with_default_rules()
}

#[test]
fn every_executed_rule_has_one_entry_and_ids_are_sorted() {
    let outcome = engine::scan_source_str(SOURCE, "lib.rs", &config(), &registry());
    assert_eq!(
        outcome.stats.rule_stats.len(),
        outcome.stats.rules_run,
        "one entry per executed rule"
    );
    let ids: Vec<&str> = outcome
        .stats
        .rule_stats
        .iter()
        .map(|stat| stat.rule_id.as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "entries are in rule id order");
}

#[test]
fn finding_counts_are_recorded() {
    let outcome = engine::scan_source_str(SOURCE, "lib.rs", &config(), &registry());
    let stat = outcome
        .stats
        .rule_stats
        .iter()
        .find(|stat| stat.rule_id == "SS-001")
        .expect("SS-001 runs and is recorded");
    assert!(stat.findings >= 1, "fixture triggers SS-001: {stat:#?}");
    assert_eq!(stat.skip_reason, None);
}

#[test]
fn skipped_rules_have_no_entry() {
    let config = ScanConfig {
        rules: RulesConfig {
            disabled: vec!["SS-001".to_string()],
            ..RulesConfig::default()
        },
        ..ScanConfig::default()
    };
    let outcome = engine::scan_source_str(SOURCE, "lib.rs", &config, &registry());
    assert!(outcome
        .stats
        .rule_stats
        .iter()
        .all(|stat| stat.rule_id != "SS-001"));
    assert_eq!(outcome.stats.rule_stats.len(), outcome.stats.rules_run);
}

#[test]
fn statistics_are_deterministic() {
    let first = engine::scan_source_str(SOURCE, "lib.rs", &config(), &registry());
    let second = engine::scan_source_str(SOURCE, "lib.rs", &config(), &registry());
    assert_eq!(first.stats.rule_stats, second.stats.rule_stats);
    assert_eq!(
        report::render_json(&first).unwrap(),
        report::render_json(&second).unwrap()
    );
}

#[test]
fn json_reports_buckets_and_no_raw_timings() {
    let outcome = engine::scan_source_str(SOURCE, "lib.rs", &config(), &registry());
    let value: serde_json::Value =
        serde_json::from_str(&report::render_json(&outcome).unwrap()).unwrap();
    let stats = value["stats"].as_object().expect("stats object");
    let entries = stats["rule_stats"].as_array().expect("rule_stats array");
    assert_eq!(entries.len(), outcome.stats.rules_run);
    for entry in entries {
        let duration = entry["duration"].as_str().expect("duration label");
        assert!(
            matches!(
                duration,
                "under_1s" | "under_10s" | "under_60s" | "at_least_60s"
            ),
            "unexpected bucket {duration}"
        );
        assert!(entry.get("elapsed_micros").is_none());
        assert!(entry.get("elapsed_nanos").is_none());
    }
    assert_eq!(stats["rule_stats_omitted"], 0);
}

struct SleepingRule {
    meta: RuleMetadata,
}

impl SleepingRule {
    fn new() -> Self {
        SleepingRule {
            meta: RuleMetadata::new(
                "SS-902",
                "Sleeping rule",
                "sleeping test rule",
                Category::Authorization,
                Severity::Low,
                Confidence::Low,
                "n/a",
            ),
        }
    }
}

impl Rule for SleepingRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn analyze(&self, _ctx: &AnalysisContext<'_>, _out: &mut Vec<Finding>) {
        std::thread::sleep(Duration::from_millis(20));
    }
}

struct PanickingRule {
    meta: RuleMetadata,
}

impl PanickingRule {
    fn new() -> Self {
        PanickingRule {
            meta: RuleMetadata::new(
                "SS-903",
                "Panicking rule",
                "panicking test rule",
                Category::Authorization,
                Severity::Low,
                Confidence::Low,
                "n/a",
            ),
        }
    }
}

impl Rule for PanickingRule {
    fn metadata(&self) -> &RuleMetadata {
        &self.meta
    }

    fn analyze(&self, _ctx: &AnalysisContext<'_>, _out: &mut Vec<Finding>) {
        panic!("intentional test panic");
    }
}

const CONTRACT: &str = "#[contractimpl]\nimpl C {\n    pub fn f(env: Env) {}\n}\n";

#[test]
fn timed_out_rules_record_a_skip_reason() {
    let mut registry = RuleRegistry::new();
    registry.register(Box::new(SleepingRule::new())).unwrap();
    let config = ScanConfig {
        rules: RulesConfig {
            rule_time_budget_ms: Some(5),
            ..RulesConfig::default()
        },
        ..ScanConfig::default()
    };
    let outcome = engine::scan_source_str(CONTRACT, "lib.rs", &config, &registry);
    assert_eq!(outcome.stats.rule_stats.len(), 1);
    assert_eq!(
        outcome.stats.rule_stats[0]
            .skip_reason
            .map(|reason| reason.as_str()),
        Some("time_budget_exceeded")
    );
}

#[test]
fn panicking_rules_record_a_skip_reason() {
    let mut registry = RuleRegistry::new();
    registry.register(Box::new(PanickingRule::new())).unwrap();
    let outcome = engine::scan_source_str(CONTRACT, "lib.rs", &config(), &registry);
    assert_eq!(outcome.stats.rule_stats.len(), 1);
    assert_eq!(
        outcome.stats.rule_stats[0]
            .skip_reason
            .map(|reason| reason.as_str()),
        Some("panicked")
    );
}
