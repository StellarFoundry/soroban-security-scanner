//! Project analysis modes (#381).
//!
//! Generic mode is opt-in and must never silently change rule behavior: the
//! effective mode is reported and a diagnostic explains which rules were
//! skipped.

use std::path::PathBuf;

use soroban_scan_core::config::{AnalysisMode, ScanConfig};
use soroban_scan_core::engine;
use soroban_scan_core::model::DiagnosticCode;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/projects")
        .join(name)
}

fn scan(name: &str, mode: AnalysisMode) -> engine::ScanOutcome {
    let config = ScanConfig {
        mode,
        ..ScanConfig::default()
    };
    engine::run_scan(&fixture(name), &config, &RuleRegistry::with_default_rules()).unwrap()
}

#[test]
fn default_mode_runs_the_soroban_rule_set() {
    let outcome = scan("generic-rust", AnalysisMode::Soroban);
    assert_eq!(outcome.stats.analysis_mode, AnalysisMode::Soroban);
    assert_eq!(outcome.stats.rules_run, 23);
    assert_eq!(outcome.stats.rules_skipped, 0);
}

#[test]
fn generic_mode_skips_soroban_only_rules_and_says_so() {
    let outcome = scan("generic-rust", AnalysisMode::Generic);
    assert_eq!(outcome.stats.analysis_mode, AnalysisMode::Generic);
    assert_eq!(outcome.stats.rules_run, 0);
    assert_eq!(outcome.stats.rules_skipped, 23);
    assert!(outcome.findings.is_empty());

    let diagnostic = outcome
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == DiagnosticCode::GenericMode)
        .expect("generic mode diagnostic");
    assert!(diagnostic.message.contains("Soroban-only"));
    assert!(diagnostic.message.contains("generic_rust"));
}

#[test]
fn auto_mode_selects_generic_only_for_plain_rust() {
    let generic = scan("generic-rust", AnalysisMode::Auto);
    assert_eq!(generic.stats.analysis_mode, AnalysisMode::Generic);
    assert_eq!(generic.stats.rules_run, 0);

    let soroban = scan("soroban-confirmed", AnalysisMode::Auto);
    assert_eq!(soroban.stats.analysis_mode, AnalysisMode::Soroban);
    assert_eq!(soroban.stats.rules_run, 23);
}

#[test]
fn generic_mode_is_visible_in_json_stats() {
    let outcome = scan("generic-rust", AnalysisMode::Generic);
    let json: serde_json::Value =
        serde_json::from_str(&report::render_json(&outcome).unwrap()).unwrap();
    assert_eq!(json["stats"]["mode"], "generic");
    assert_eq!(json["stats"]["rules_run"], 0);
}
