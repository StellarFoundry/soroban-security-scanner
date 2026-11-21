//! Security regression corpus with explicit expected-findings manifests (#137).
//!
//! Every built-in rule directory contains `expected.json`, listing every fixture
//! file and the exact findings it must produce (rule id, count, and severity).
//! The manifest makes regression intent reviewable and can express counts and
//! multi-rule files, which the old "positive must trigger / negative must not"
//! convention could not.
//!
//! Manifests are generated from the current behavior only when an intentional
//! change is being reviewed:
//!
//! ```text
//! UPDATE_EXPECTATIONS=1 cargo test -p soroban-scan-core --test corpus
//! ```
//!
//! On PowerShell:
//!
//! ```text
//! $env:UPDATE_EXPECTATIONS="1"; cargo test -p soroban-scan-core --test corpus
//! ```
//!
//! Review the diff before committing. Never regenerate manifests merely to make
//! an unrelated test pass.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::severity::Severity;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus")
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("expected.json")
}

fn fixture_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            let expected_prefix = name.starts_with("positive") || name.starts_with("negative");
            let corpus_ext = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext == "rs" || ext == "toml");
            expected_prefix && corpus_ext
        })
        .collect();
    files.sort();
    files
}

fn safe_file_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('/')
        && !name.contains('\\')
        && (name.starts_with("positive") || name.starts_with("negative"))
}

#[derive(Debug, Serialize, Deserialize)]
struct Manifest {
    schema_version: u32,
    rule_id: String,
    #[serde(default)]
    fixtures: Vec<FixtureExpectation>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FixtureExpectation {
    file: String,
    #[serde(default)]
    findings: Vec<ExpectedFinding>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ExpectedFinding {
    rule_id: String,
    count: usize,
    severity: String,
    #[serde(default)]
    confidence: Option<String>,
}

fn scan_fixture(
    path: &Path,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> BTreeMap<String, (usize, String)> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fixture");
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let outcome = if path.extension().is_some_and(|ext| ext == "toml") {
        engine::scan_manifest_str("Cargo.toml", &source, config, registry)
            .unwrap_or_else(|error| panic!("{}: manifest fixture failed: {error}", path.display()))
    } else {
        engine::scan_source_str(&source, file_name, config, registry)
    };

    let mut counts: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for finding in outcome.findings {
        let entry = counts
            .entry(finding.rule_id)
            .or_insert_with(|| (0, finding.severity.as_str().to_string()));
        entry.0 += 1;
    }
    counts
}

fn generate_manifest(
    dir: &Path,
    rule_id: &str,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> String {
    let fixtures = fixture_files(dir)
        .into_iter()
        .map(|path| {
            let file = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fixture")
                .to_string();
            let findings = scan_fixture(&path, config, registry)
                .into_iter()
                .map(|(rule_id, (count, severity))| ExpectedFinding {
                    rule_id,
                    count,
                    severity,
                    confidence: None,
                })
                .collect();
            FixtureExpectation { file, findings }
        })
        .collect();
    let manifest = Manifest {
        schema_version: 1,
        rule_id: rule_id.to_string(),
        fixtures,
    };
    let mut text = serde_json::to_string_pretty(&manifest).expect("serialize manifest");
    text.push('\n');
    text
}

fn validate_manifest(
    manifest: &Manifest,
    dir: &Path,
    rule_id: &str,
    registry: &RuleRegistry,
) -> Vec<String> {
    let mut issues = Vec::new();
    if manifest.schema_version != 1 {
        issues.push(format!(
            "{rule_id}: unsupported manifest schema_version {}",
            manifest.schema_version
        ));
    }
    if manifest.rule_id != rule_id {
        issues.push(format!(
            "{rule_id}: manifest rule_id `{}` does not match the directory",
            manifest.rule_id
        ));
    }

    let actual_files: BTreeSet<String> = fixture_files(dir)
        .into_iter()
        .filter_map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .map(str::to_string)
        })
        .collect();
    let mut listed: BTreeSet<String> = BTreeSet::new();
    for fixture in &manifest.fixtures {
        if !safe_file_name(&fixture.file) {
            issues.push(format!(
                "{rule_id}: unsafe or unexpected fixture path `{}`",
                fixture.file
            ));
            continue;
        }
        if !listed.insert(fixture.file.clone()) {
            issues.push(format!(
                "{rule_id}: duplicate fixture entry `{}`",
                fixture.file
            ));
        }
        if !actual_files.contains(&fixture.file) {
            issues.push(format!(
                "{rule_id}: manifest lists missing fixture `{}`",
                fixture.file
            ));
        }
        let mut seen_rules = BTreeSet::new();
        for finding in &fixture.findings {
            if registry.by_id(&finding.rule_id).is_none() {
                issues.push(format!(
                    "{rule_id}: fixture `{}` expects unknown rule `{}`",
                    fixture.file, finding.rule_id
                ));
            }
            if finding.count == 0 {
                issues.push(format!(
                    "{rule_id}: fixture `{}` has a zero expected count",
                    fixture.file
                ));
            }
            if finding.severity.parse::<Severity>().is_err() {
                issues.push(format!(
                    "{rule_id}: fixture `{}` has invalid severity `{}`",
                    fixture.file, finding.severity
                ));
            }
            if let Some(confidence) = &finding.confidence {
                if confidence
                    .parse::<soroban_scan_core::confidence::Confidence>()
                    .is_err()
                {
                    issues.push(format!(
                        "{rule_id}: fixture `{}` has invalid confidence `{confidence}`",
                        fixture.file
                    ));
                }
            }
            if !seen_rules.insert(finding.rule_id.clone()) {
                issues.push(format!(
                    "{rule_id}: fixture `{}` lists rule `{}` more than once",
                    fixture.file, finding.rule_id
                ));
            }
        }
    }
    for missing in actual_files.difference(&listed) {
        issues.push(format!(
            "{rule_id}: fixture `{missing}` has no manifest entry"
        ));
    }
    issues
}

#[test]
fn positive_and_negative_fixtures_match_expectations() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let base = corpus_dir();
    let update = std::env::var("UPDATE_EXPECTATIONS").as_deref() == Ok("1");
    let mut failures = Vec::new();

    for meta in registry.metadata_sorted() {
        let dir = base.join(meta.id);
        if !dir.is_dir() {
            failures.push(format!("{}: missing corpus directory", meta.id));
            continue;
        }

        if update {
            let text = generate_manifest(&dir, meta.id, &config, &registry);
            std::fs::write(manifest_path(&dir), text)
                .unwrap_or_else(|error| panic!("{}: cannot write manifest: {error}", meta.id));
        }

        let manifest_text = std::fs::read_to_string(manifest_path(&dir)).unwrap_or_else(|error| {
            panic!(
                "{}: cannot read expected.json: {error}. Generate it with \
                 UPDATE_EXPECTATIONS=1 cargo test -p soroban-scan-core --test corpus",
                meta.id
            )
        });
        let manifest: Manifest = serde_json::from_str(&manifest_text)
            .unwrap_or_else(|error| panic!("{}: invalid expected.json: {error}", meta.id));
        failures.extend(validate_manifest(&manifest, &dir, meta.id, &registry));

        let mut positive_count = 0usize;
        let mut negative_count = 0usize;
        for fixture in &manifest.fixtures {
            if fixture.file.starts_with("positive") {
                positive_count += 1;
            } else if fixture.file.starts_with("negative") {
                negative_count += 1;
            }

            let path = dir.join(&fixture.file);
            let actual = scan_fixture(&path, &config, &registry);
            let expected: BTreeMap<String, (usize, String)> = fixture
                .findings
                .iter()
                .map(|finding| {
                    (
                        finding.rule_id.clone(),
                        (finding.count, finding.severity.clone()),
                    )
                })
                .collect();
            if actual != expected {
                failures.push(format!(
                    "{}: fixture `{}` findings changed: expected {:?}, got {:?}",
                    meta.id, fixture.file, expected, actual
                ));
            }

            let target_hits = actual.get(meta.id).map(|(count, _)| *count).unwrap_or(0);
            if fixture.file.starts_with("positive") && target_hits == 0 {
                failures.push(format!(
                    "{}: positive fixture `{}` does not trigger the rule",
                    meta.id, fixture.file
                ));
            }
            if fixture.file.starts_with("negative") && target_hits != 0 {
                failures.push(format!(
                    "{}: negative fixture `{}` triggers the rule",
                    meta.id, fixture.file
                ));
            }
        }
        if positive_count == 0 {
            failures.push(format!("{}: missing positive fixture", meta.id));
        }
        if negative_count < 3 {
            failures.push(format!(
                "{}: at least three negative fixtures are required",
                meta.id
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "corpus manifest failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn manifests_are_valid() {
    if std::env::var("UPDATE_EXPECTATIONS").as_deref() == Ok("1") {
        return;
    }
    let registry = RuleRegistry::with_default_rules();
    let base = corpus_dir();
    let mut issues = Vec::new();
    for meta in registry.metadata_sorted() {
        let dir = base.join(meta.id);
        let text = std::fs::read_to_string(manifest_path(&dir))
            .unwrap_or_else(|error| panic!("{}: cannot read manifest: {error}", meta.id));
        let manifest: Manifest = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{}: invalid manifest: {error}", meta.id));
        issues.extend(validate_manifest(&manifest, &dir, meta.id, &registry));
    }
    assert!(issues.is_empty(), "manifest issues:\n{}", issues.join("\n"));
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
