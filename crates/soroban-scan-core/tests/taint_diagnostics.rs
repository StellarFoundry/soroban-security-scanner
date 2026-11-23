//! Taint diagnostics for unresolved flows (#286).
//!
//! The engine must surface why a taint flow may be missing, in a bounded,
//! aggregated form that never includes source text.

use std::path::PathBuf;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::model::DiagnosticCode;
use soroban_scan_core::registry::RuleRegistry;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/taint")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn engine_reports_unsupported_taint_flows_without_source_text() {
    let source = fixture("unsupported_flow.rs");
    let outcome = engine::scan_source_str(
        &source,
        "unsupported_flow.rs",
        &ScanConfig::default(),
        &RuleRegistry::with_default_rules(),
    );
    let diagnostics: Vec<_> = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::TaintIncomplete)
        .collect();
    assert!(!diagnostics.is_empty(), "expected a TAINT-001 diagnostic");
    assert!(diagnostics
        .iter()
        .all(|diagnostic| !diagnostic.message.contains("value =>")
            && !diagnostic.message.contains("match amount")));
    assert!(diagnostics.len() <= soroban_scan_core::analysis::taint::MAX_TAINT_DIAGNOSTICS);
}
