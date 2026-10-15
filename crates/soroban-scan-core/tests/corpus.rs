//! Security regression corpus.
//!
//! For every built-in rule, `fixtures/corpus/<RULE-ID>/positive.rs` must
//! trigger the rule and `negative.rs` must not. This pins detector behavior and
//! catches false positives.

use std::path::PathBuf;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus")
}

#[test]
fn positive_and_negative_fixtures_match_expectations() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let base = corpus_dir();
    let mut checked = 0;

    for meta in registry.metadata_sorted() {
        let dir = base.join(meta.id);
        let positive = std::fs::read_to_string(dir.join("positive.rs"))
            .unwrap_or_else(|_| panic!("missing positive fixture for {}", meta.id));

        let pos = engine::scan_source_str(&positive, "positive.rs", &config, &registry);
        let pos_hits: Vec<_> = pos
            .findings
            .iter()
            .filter(|f| f.rule_id == meta.id)
            .collect();
        assert!(
            !pos_hits.is_empty(),
            "{}: positive fixture did not trigger the rule",
            meta.id
        );

        // Every `negative*.rs` fixture in the rule's directory must not
        // trigger the rule. This allows adding extra negatives (negative2.rs,
        // negative3.rs, …) without touching the test.
        let negatives: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|_| panic!("missing corpus dir for {}", meta.id))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("negative") && name.ends_with(".rs"))
            })
            .collect();

        assert!(
            !negatives.is_empty(),
            "{}: at least one negative fixture is required",
            meta.id
        );
        for negative_path in negatives {
            let negative_name = negative_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let negative = std::fs::read_to_string(&negative_path).unwrap_or_else(|_| {
                panic!("missing negative fixture {} for {}", negative_name, meta.id)
            });

            let neg = engine::scan_source_str(&negative, &negative_name, &config, &registry);
            let neg_hits: Vec<_> = neg
                .findings
                .iter()
                .filter(|f| f.rule_id == meta.id)
                .collect();
            assert!(
                neg_hits.is_empty(),
                "{}: negative fixture {} triggered the rule: {:?}",
                meta.id,
                negative_name,
                neg_hits.iter().map(|f| &f.evidence).collect::<Vec<_>>()
            );
        }

        checked += 1;
    }

    assert_eq!(checked, 10, "expected fixtures for all built-in rules");
}

#[test]
fn corpus_scanning_is_deterministic() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let src = std::fs::read_to_string(corpus_dir().join("SS-001/positive.rs")).unwrap();
    let a = engine::scan_source_str(&src, "positive.rs", &config, &registry);
    let b = engine::scan_source_str(&src, "positive.rs", &config, &registry);
    assert_eq!(
        serde_json::to_string(&a.findings).unwrap(),
        serde_json::to_string(&b.findings).unwrap()
    );
}

#[test]
fn malformed_source_does_not_panic() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let outcome = engine::scan_source_str("fn broken( {", "broken.rs", &config, &registry);
    assert!(outcome.findings.is_empty());
    assert!(outcome
        .diagnostics
        .iter()
        .any(|d| d.message.contains("failed to parse")));
}
