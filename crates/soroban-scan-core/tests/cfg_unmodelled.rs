//! Bounded diagnostics for constructs the CFG does not model (#298).
//!
//! The diagnostics aggregate counts per kind, are capped, and never carry
//! source text or a path.

use soroban_scan_core::analysis::cfg::MAX_CFG_DIAGNOSTICS;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::model::{Diagnostic, DiagnosticCode};
use soroban_scan_core::registry::RuleRegistry;

const SOURCE: &str = r#"
#[contractimpl]
impl C {
    pub fn run(env: Env) {
        first_macro!();
        second_macro!();
        third_macro!();
        fn nested() {}
        loop { break; }
        async { 1 };
    }
}
"#;

fn scan(source: &str) -> Vec<Diagnostic> {
    let outcome = engine::scan_source_str(
        source,
        "src/lib.rs",
        &ScanConfig::default(),
        &RuleRegistry::with_default_rules(),
    );
    outcome
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::CfgUnmodelled)
        .collect()
}

#[test]
fn unmodelled_constructs_are_aggregated_by_kind() {
    let diagnostics = scan(SOURCE);
    assert_eq!(diagnostics.len(), 5, "got: {diagnostics:#?}");

    let messages: Vec<&str> = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect();
    assert!(messages
        .iter()
        .any(|message| message.contains("3 control-flow construct(s) of kind `macro`")));
    assert!(messages
        .iter()
        .any(|message| message.contains("1 control-flow construct(s) of kind `item`")));
    assert!(messages
        .iter()
        .any(|message| message.contains("1 control-flow construct(s) of kind `break`")));
    assert!(messages
        .iter()
        .any(|message| message.contains("1 control-flow construct(s) of kind `async`")));
    assert!(messages
        .iter()
        .any(|message| message.contains("1 control-flow construct(s) of kind `loop_exit`")));
}

#[test]
fn unmodelled_diagnostics_carry_no_source_text_or_path() {
    let diagnostics = scan(SOURCE);
    assert!(!diagnostics.is_empty());
    for diagnostic in &diagnostics {
        assert_eq!(diagnostic.path, None, "no path: {diagnostic:#?}");
        assert_eq!(diagnostic.line, None, "no line: {diagnostic:#?}");
        for fragment in [
            "first_macro",
            "second_macro",
            "third_macro",
            "nested",
            "src/lib.rs",
            "pub fn",
        ] {
            assert!(
                !diagnostic.message.contains(fragment),
                "message leaks {fragment:?}: {}",
                diagnostic.message
            );
        }
    }
}

#[test]
fn unmodelled_diagnostics_are_bounded() {
    let diagnostics = scan(SOURCE);
    assert!(diagnostics.len() <= MAX_CFG_DIAGNOSTICS);
}

#[test]
fn unmodelled_diagnostics_are_deterministic() {
    assert_eq!(scan(SOURCE), scan(SOURCE));
}

#[test]
fn generic_mode_does_not_emit_unmodelled_cfg_diagnostics() {
    let source = "fn helper() { some_macro!(); }";
    assert!(scan(source).is_empty());
}
