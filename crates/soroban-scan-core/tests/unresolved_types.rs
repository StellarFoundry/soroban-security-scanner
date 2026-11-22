//! Bounded `TYPE-001` diagnostics for unresolved types (#277).

use soroban_scan_core::analysis::types::MAX_TYPE_DIAGNOSTICS;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::model::{Diagnostic, DiagnosticCode};
use soroban_scan_core::registry::RuleRegistry;

fn type_diagnostics(source: &str) -> Vec<Diagnostic> {
    let registry = RuleRegistry::with_default_rules();
    let outcome = engine::scan_source_str(source, "src/lib.rs", &ScanConfig::default(), &registry);
    outcome
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::UnresolvedType)
        .collect()
}

#[test]
fn aggregates_repeated_types_and_keeps_the_first_span() {
    let diagnostics = type_diagnostics(
        r#"
        use soroban_sdk::{contractimpl, Env};

        #[contractimpl]
        impl C {
            pub fn set(env: Env) {
                let first: Mystery = 1;
                let second: Mystery = 2;
                let _ = (first, second, env);
            }
        }
        "#,
    );
    let mystery: Vec<_> = diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.message.contains("Mystery"))
        .collect();
    assert_eq!(mystery.len(), 1, "got: {diagnostics:#?}");
    assert!(mystery[0].message.contains("2 occurrences"));
    assert_eq!(
        mystery[0].path.as_deref(),
        Some(std::path::Path::new("src/lib.rs"))
    );
    assert_eq!(mystery[0].line, Some(7));
    assert!(mystery[0].column.unwrap_or(0) > 0);
}

#[test]
fn output_is_bounded_on_large_sources() {
    let mut body = String::new();
    for index in 0..(MAX_TYPE_DIAGNOSTICS * 4) {
        body.push_str(&format!(
            "                let value_{index}: Missing{index} = 1;\n"
        ));
    }
    let source = format!(
        "use soroban_sdk::{{contractimpl, Env}};\n\n\
         #[contractimpl]\n\
         impl C {{\n\
             pub fn set(env: Env) {{\n{body}                let _ = env;\n            }}\n\
         }}\n"
    );
    let diagnostics = type_diagnostics(&source);
    assert!(
        diagnostics.len() <= MAX_TYPE_DIAGNOSTICS + 1,
        "got {} diagnostics",
        diagnostics.len()
    );
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("omitted")));
}

#[test]
fn repeated_scans_produce_identical_diagnostics() {
    let source = r#"
        use soroban_sdk::{contractimpl, Env};

        #[contractimpl]
        impl C {
            pub fn set(env: Env, amount: Amount) {
                let _ = amount as Target;
                let _ = env;
            }
        }
        "#;
    let first = type_diagnostics(source);
    let second = type_diagnostics(source);
    assert_eq!(first, second);
    assert!(!first.is_empty());
}
