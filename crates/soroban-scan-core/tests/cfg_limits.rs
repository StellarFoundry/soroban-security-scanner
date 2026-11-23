//! Bounded CFG behaviour (#297): truncation is reported as a diagnostic, and
//! consumers skip a truncated graph instead of making a partial claim.

use std::path::PathBuf;

use soroban_scan_core::analysis::cfg::MAX_CFG_DIAGNOSTICS;
use soroban_scan_core::config::{RulesConfig, ScanConfig};
use soroban_scan_core::engine;
use soroban_scan_core::model::DiagnosticCode;
use soroban_scan_core::registry::RuleRegistry;

fn large_contract(functions: usize) -> String {
    let mut source = String::from("#[contractimpl]\nimpl C {\n");
    for index in 0..functions {
        source.push_str(&format!(
            "    pub fn f{index}(env: Env, admin: Address) {{\n"
        ));
        for statement in 0..300 {
            source.push_str(&format!("        let _ = {statement}u32;\n"));
        }
        source.push_str("    }\n");
    }
    source.push_str("}\n");
    source
}

#[test]
fn truncated_cfg_emits_a_bounded_diagnostic() {
    let registry = RuleRegistry::with_default_rules();
    let source = large_contract(1);
    let outcome = engine::scan_source_str(&source, "src/lib.rs", &ScanConfig::default(), &registry);

    let diagnostics: Vec<_> = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::CfgTruncated)
        .collect();
    assert_eq!(diagnostics.len(), 1, "got: {diagnostics:#?}");
    let diagnostic = diagnostics[0];
    assert!(diagnostic.message.contains("was truncated"));
    assert!(diagnostic.message.contains("caps:"));
    assert_eq!(diagnostic.path, Some(PathBuf::from("src/lib.rs")));
    assert!(diagnostic.line.is_some());
}

#[test]
fn truncation_diagnostics_are_capped_with_an_omitted_notice() {
    let registry = RuleRegistry::with_default_rules();
    let source = large_contract(MAX_CFG_DIAGNOSTICS + 4);
    let outcome = engine::scan_source_str(&source, "src/lib.rs", &ScanConfig::default(), &registry);

    let diagnostics: Vec<_> = outcome
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::CfgTruncated)
        .collect();
    assert_eq!(diagnostics.len(), MAX_CFG_DIAGNOSTICS + 1);
    assert!(diagnostics
        .last()
        .expect("omitted notice")
        .message
        .contains("additional control-flow graph truncation diagnostic(s) omitted"));
}

#[test]
fn unreachable_check_rule_skips_a_truncated_graph() {
    let mut source = String::from(
        "#[contractimpl]\nimpl C {\n    pub fn set(env: Env, admin: Address) {\n        return;\n        admin.require_auth();\n",
    );
    for statement in 0..300 {
        source.push_str(&format!("        let _ = {statement}u32;\n"));
    }
    source.push_str("    }\n}\n");

    let config = ScanConfig {
        rules: RulesConfig {
            enabled: vec!["SS-042".to_string()],
            ..Default::default()
        },
        ..ScanConfig::default()
    };
    let registry = RuleRegistry::with_default_rules();
    let outcome = engine::scan_source_str(&source, "src/lib.rs", &config, &registry);

    assert!(
        outcome
            .findings
            .iter()
            .all(|finding| finding.rule_id != "SS-042"),
        "a truncated graph must not produce a partial unreachability claim: {:#?}",
        outcome.findings
    );
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::CfgTruncated));
}
