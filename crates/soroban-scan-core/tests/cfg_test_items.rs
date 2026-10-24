//! `#[cfg(...)]` handling: attributes are recorded as tokens (never
//! evaluated), and `cfg(test)` items are skipped unless explicitly included.

use std::path::{Path, PathBuf};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::source::parse_source_with_options;

fn fixture() -> (String, String) {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/parser/cfg_test_gated.rs");
    (
        std::fs::read_to_string(&path).expect("fixture must exist"),
        "src/lib.rs".to_string(),
    )
}

fn flagged_functions(config: &ScanConfig) -> Vec<String> {
    let (src, name) = fixture();
    let registry = RuleRegistry::with_default_rules();
    let report = engine::scan_source_str(&src, &name, config, &registry);
    let names: Vec<String> = report
        .findings
        .iter()
        .filter(|f| f.rule_id == "SS-001")
        .map(|f| f.title.clone())
        .collect();
    names
}

#[test]
fn cfg_attributes_are_recorded_as_raw_tokens() {
    let (src, _) = fixture();
    let parsed = parse_source_with_options(Path::new("src/lib.rs"), Path::new("."), &src, false);
    let by_name = |n: &str| {
        parsed
            .functions
            .iter()
            .find(|f| f.name == n)
            .unwrap_or_else(|| panic!("missing {n}"))
    };
    assert_eq!(by_name("test_reset").cfg_attrs, vec!["test".to_string()]);
    assert_eq!(
        by_name("set_fee").cfg_attrs,
        vec!["feature = \"extras\"".to_string()]
    );
    assert!(by_name("set_admin").cfg_attrs.is_empty());
    let module = parsed
        .items
        .iter()
        .find(|i| i.name == "tests")
        .expect("module item");
    assert_eq!(module.cfg_attrs, vec!["test".to_string()]);
}

#[test]
fn cfg_expressions_are_not_evaluated() {
    let src = "#[cfg(all(unix, not(test)))]\nfn f() {}\n#[cfg(any())]\nfn g() {}\n";
    let parsed = parse_source_with_options(Path::new("a.rs"), Path::new("."), src, false);
    let f = parsed.functions.iter().find(|f| f.name == "f").unwrap();
    assert_eq!(f.cfg_attrs.len(), 1);
    assert!(f.cfg_attrs[0].contains("unix"));
    // `cfg(any())` is never true, yet the item is still inventoried.
    assert!(parsed.functions.iter().any(|f| f.name == "g"));
}

#[test]
fn detectors_skip_cfg_test_items_by_default() {
    let config = ScanConfig::default();
    let default_findings = flagged_functions(&config);
    let included = flagged_functions(&ScanConfig {
        include_cfg_test: true,
        ..ScanConfig::default()
    });
    assert_eq!(default_findings.len(), 2, "{default_findings:?}");
    assert_eq!(included.len(), 4, "{included:?}");
    // Non-test cfg code (`cfg(feature = ...)`) is still scanned by default.
    let (src, _) = fixture();
    let parsed = parse_source_with_options(Path::new("src/lib.rs"), Path::new("."), &src, true);
    let names: Vec<_> = parsed.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(names.contains(&"set_admin"));
    assert!(names.contains(&"set_fee"));
    assert!(!names.contains(&"test_reset"));
    assert!(!names.contains(&"seed"));
}
