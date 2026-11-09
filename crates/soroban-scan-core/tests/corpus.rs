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
        if meta.id == "SS-015" {
            let positive = std::fs::read_to_string(dir.join("positive.toml"))
                .unwrap_or_else(|_| panic!("missing positive.toml for {}", meta.id));
            let pos = engine::scan_manifest_str("Cargo.toml", &positive, &config, &registry)
                .expect("manifest fixture must parse");
            assert!(
                pos.findings
                    .iter()
                    .any(|finding| finding.rule_id == meta.id),
                "{}: positive manifest fixture did not trigger the rule",
                meta.id
            );

            let negatives: Vec<_> = std::fs::read_dir(&dir)
                .unwrap()
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with("negative") && name.ends_with(".toml"))
                })
                .collect();
            assert!(
                negatives.len() >= 3,
                "{}: at least three negative fixtures are required",
                meta.id
            );
            for negative_path in negatives {
                let negative = std::fs::read_to_string(&negative_path).unwrap();
                let neg = engine::scan_manifest_str("Cargo.toml", &negative, &config, &registry)
                    .expect("manifest fixture must parse");
                assert!(
                    !neg.findings
                        .iter()
                        .any(|finding| finding.rule_id == meta.id),
                    "{}: negative manifest fixture triggered the rule",
                    meta.id
                );
            }
            checked += 1;
            continue;
        }
        let mut positives: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|_| panic!("missing corpus dir for {}", meta.id))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("positive") && name.ends_with(".rs"))
            })
            .collect();
        positives.sort();
        assert!(
            !positives.is_empty(),
            "{}: missing positive fixture",
            meta.id
        );

        for positive_path in positives {
            let positive_name = positive_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let positive = std::fs::read_to_string(&positive_path).unwrap_or_else(|_| {
                panic!("missing positive fixture {} for {}", positive_name, meta.id)
            });
            let pos = engine::scan_source_str(&positive, &positive_name, &config, &registry);
            let pos_hits: Vec<_> = pos
                .findings
                .iter()
                .filter(|f| f.rule_id == meta.id)
                .collect();
            assert!(
                !pos_hits.is_empty(),
                "{}: positive fixture {} did not trigger the rule",
                meta.id,
                positive_name
            );
        }

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
            negatives.len() >= 3,
            "{}: at least three negative fixtures are required",
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

    assert_eq!(
        checked,
        registry.metadata_sorted().len(),
        "expected fixtures for all built-in rules"
    );
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

#[test]
fn every_detector_has_documented_must_trigger_recall_fixture() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let base = corpus_dir();

    for meta in registry.metadata_sorted() {
        let dir = base.join(meta.id);
        let expected_ext = if meta.id == "SS-015" { ".toml" } else { ".rs" };
        let mut must_triggers: Vec<PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|_| panic!("missing corpus dir for {}", meta.id))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| {
                        (name.starts_with("must-trigger") || name.starts_with("must_trigger"))
                            && name.ends_with(expected_ext)
                    })
            })
            .collect();
        must_triggers.sort();
        assert!(
            !must_triggers.is_empty(),
            "{}: missing must-trigger recall fixture in {}",
            meta.id,
            dir.display()
        );

        for fixture_path in must_triggers {
            let fixture_name = fixture_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let content = std::fs::read_to_string(&fixture_path).unwrap_or_else(|_| {
                panic!(
                    "cannot read must-trigger fixture {} for {}",
                    fixture_name, meta.id
                )
            });
            assert!(
                content.contains("Rationale:"),
                "{}: must-trigger fixture {} must document its true-positive Rationale",
                meta.id,
                fixture_name
            );

            let outcome = if meta.id == "SS-015" {
                engine::scan_manifest_str("Cargo.toml", &content, &config, &registry)
                    .expect("must-trigger manifest fixture must parse")
            } else {
                engine::scan_source_str(&content, &fixture_name, &config, &registry)
            };

            assert!(
                outcome.findings.iter().any(|f| f.rule_id == meta.id),
                "{}: must-trigger recall fixture {} failed to trigger detector (false negative!)",
                meta.id,
                fixture_name
            );
        }
    }
}
