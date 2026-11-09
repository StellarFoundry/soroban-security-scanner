//! Adversarial and pathological input tests.
//!
//! The scanner must never panic, hang, or fabricate findings on hostile input.

use std::time::{Duration, Instant};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

fn scan(src: &str) -> engine::ScanOutcome {
    let registry = RuleRegistry::with_default_rules();
    engine::scan_source_str(src, "adversarial.rs", &ScanConfig::default(), &registry)
}

#[test]
fn empty_and_whitespace_sources_are_safe() {
    for src in ["", "   \n\t  ", "// just a comment\n", "/* block */\n"] {
        let outcome = scan(src);
        assert!(outcome.findings.is_empty());
    }
}

#[test]
fn deeply_nested_structure_does_not_panic() {
    let depth = 200;
    let src = format!("fn f() {{ {} 0 {} }}", "(".repeat(depth), ")".repeat(depth));
    let outcome = scan(&src);
    assert!(outcome.findings.is_empty());
}

#[test]
fn very_long_line_does_not_panic() {
    let src = format!("fn f() {{ let x = \"{}\"; }}", "a".repeat(100_000));
    let outcome = scan(&src);
    assert!(outcome.findings.is_empty());
}

#[test]
fn unicode_identifiers_do_not_panic() {
    let src = "#[contractimpl]\nimpl C { pub fn \u{03b2}(\u{03b1}: u32) -> u32 { \u{03b1} } }\n";
    let _ = scan(src);
}

#[test]
fn many_entry_points_complete_quickly() {
    let mut src = String::from("#[contractimpl]\nimpl C {\n");
    for i in 0..2_000 {
        src.push_str(&format!(
            "    pub fn f{i}(env: Env) {{ env.storage().persistent().set(&K{i}, &{i}); }}\n"
        ));
    }
    src.push_str("}\n");

    let start = Instant::now();
    let outcome = scan(&src);
    let elapsed = start.elapsed();

    assert!(!outcome.findings.is_empty());
    assert!(
        elapsed < Duration::from_secs(30),
        "scan took too long: {elapsed:?}"
    );
}

#[test]
fn repeated_scans_are_byte_identical() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/corpus/SS-001/positive.rs"
    ))
    .unwrap();
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let first = serde_json::to_string(
        &engine::scan_source_str(&src, "positive.rs", &config, &registry).findings,
    )
    .unwrap();
    for _ in 0..5 {
        let again = serde_json::to_string(
            &engine::scan_source_str(&src, "positive.rs", &config, &registry).findings,
        )
        .unwrap();
        assert_eq!(first, again);
    }
}

#[test]
fn every_detector_has_documented_adversarial_fixture() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let base = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/adversarial");

    for meta in registry.metadata_sorted() {
        let dir = base.join(meta.id);
        let fixture_path = if meta.id == "SS-015" {
            dir.join("adversarial.toml")
        } else {
            dir.join("adversarial.rs")
        };
        assert!(
            fixture_path.exists(),
            "{}: missing adversarial fixture at {}",
            meta.id,
            fixture_path.display()
        );

        let content = std::fs::read_to_string(&fixture_path)
            .unwrap_or_else(|e| panic!("{}: cannot read {}: {e}", meta.id, fixture_path.display()));
        assert!(
            content.contains("Technique:"),
            "{}: adversarial fixture must document `Technique:`",
            meta.id
        );
        let expect_trigger = if content.contains("Expected: trigger") {
            true
        } else if content.contains("Expected: no-trigger") {
            false
        } else {
            panic!(
                "{}: adversarial fixture must document `Expected: trigger` or `Expected: no-trigger`",
                meta.id
            );
        };

        let start = Instant::now();
        let outcome = if meta.id == "SS-015" {
            engine::scan_manifest_str("Cargo.toml", &content, &config, &registry)
                .expect("adversarial manifest must parse")
        } else {
            engine::scan_source_str(&content, "adversarial.rs", &config, &registry)
        };
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "{}: adversarial fixture took too long: {elapsed:?}",
            meta.id
        );

        let triggered = outcome.findings.iter().any(|f| f.rule_id == meta.id);
        assert_eq!(
            triggered, expect_trigger,
            "{}: adversarial fixture expectation mismatch (expected trigger={expect_trigger}, got {triggered})",
            meta.id
        );
    }
}
