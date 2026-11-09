//! Security regression corpus.
//!
//! For every built-in rule, `fixtures/corpus/<RULE-ID>/positive.rs` must
//! trigger the rule and `negative.rs` must not. This pins detector behavior and
//! catches false positives.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use soroban_scan_core::confidence::Confidence;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::finding::Finding;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::severity::Severity;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusManifest {
    schema_version: String,
    rule_id: String,
    expected: Vec<ExpectedFinding>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedFinding {
    rule_id: String,
    file: String,
    line: usize,
    severity: Severity,
    confidence: Confidence,
    #[serde(default)]
    evidence_contains: Option<String>,
}

fn load_manifest(dir: &Path, rule_id: &str) -> CorpusManifest {
    let manifest_path = dir.join("expected.json");
    let raw = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("{rule_id}: missing corpus manifest {}: {e}", manifest_path.display()));
    let manifest: CorpusManifest = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("{rule_id}: invalid corpus manifest {}: {e}", manifest_path.display()));
    assert_eq!(
        manifest.schema_version, "1",
        "{rule_id}: unsupported corpus manifest schema_version {}",
        manifest.schema_version
    );
    assert_eq!(
        manifest.rule_id, rule_id,
        "{rule_id}: corpus manifest rule_id mismatch (got {})",
        manifest.rule_id
    );
    assert!(
        !manifest.expected.is_empty(),
        "{rule_id}: corpus manifest must declare at least one expected finding"
    );
    manifest
}

fn assert_expected_findings(
    rule_id: &str,
    fixture_file: &str,
    expected_entries: &[&ExpectedFinding],
    actual_findings: &[&Finding],
) {
    assert_eq!(
        actual_findings.len(),
        expected_entries.len(),
        "{rule_id} ({fixture_file}): finding count mismatch: expected {}, got {}",
        expected_entries.len(),
        actual_findings.len()
    );
    for expected in expected_entries {
        assert_eq!(
            expected.rule_id, rule_id,
            "{rule_id} ({fixture_file}): expected entry rule_id {} must match rule directory",
            expected.rule_id
        );
        let matched = actual_findings.iter().find(|finding| {
            finding.rule_id == expected.rule_id
                && finding.location.line == expected.line
                && finding.severity == expected.severity
                && finding.confidence == expected.confidence
                && expected
                    .evidence_contains
                    .as_deref()
                    .is_none_or(|needle| finding.evidence.contains(needle))
        });
        assert!(
            matched.is_some(),
            "{rule_id} ({fixture_file}): missing expected finding at line {} (severity={:?}, confidence={:?}, evidence_contains={:?}); actual={:#?}",
            expected.line,
            expected.severity,
            expected.confidence,
            expected.evidence_contains,
            actual_findings
        );
    }
}

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
        let manifest = load_manifest(&dir, meta.id);
        if meta.id == "SS-015" {
            let positive = std::fs::read_to_string(dir.join("positive.toml"))
                .unwrap_or_else(|_| panic!("missing positive.toml for {}", meta.id));
            let pos = engine::scan_manifest_str("Cargo.toml", &positive, &config, &registry)
                .expect("manifest fixture must parse");
            let pos_hits: Vec<_> = pos
                .findings
                .iter()
                .filter(|finding| finding.rule_id == meta.id)
                .collect();
            assert!(
                !pos_hits.is_empty(),
                "{}: positive manifest fixture did not trigger the rule",
                meta.id
            );
            let expected_for_file: Vec<_> = manifest
                .expected
                .iter()
                .filter(|e| e.file == "positive.toml" || e.file == "Cargo.toml")
                .collect();
            assert_expected_findings(meta.id, "positive.toml", &expected_for_file, &pos_hits);

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
            let expected_for_file: Vec<_> = manifest
                .expected
                .iter()
                .filter(|e| e.file == positive_name)
                .collect();
            assert_expected_findings(meta.id, &positive_name, &expected_for_file, &pos_hits);
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
