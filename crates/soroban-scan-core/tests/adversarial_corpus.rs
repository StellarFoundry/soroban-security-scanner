//! Adversarial rule corpus (#143).
//!
//! Every built-in detector has a sample written with valid but unusual syntax.
//! `fixtures/adversarial/expectations.toml` records whether the sample must
//! trigger the rule or documents a known no-trigger limit. The rule list comes
//! from the registry, so a new detector without a fixture fails here.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

#[derive(Deserialize)]
struct Expectation {
    file: String,
    expect: String,
    why: String,
}

fn adversarial_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/adversarial")
}

fn expectations() -> BTreeMap<String, Expectation> {
    let path = adversarial_dir().join("expectations.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    toml::from_str(&text).unwrap_or_else(|error| panic!("invalid expectations.toml: {error}"))
}

fn safe_relative(path: &str) -> bool {
    Path::new(path)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

#[test]
fn adversarial_fixtures_match_expectations() {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let expectations = expectations();
    let base = adversarial_dir();

    let registered: BTreeSet<String> = registry
        .metadata_sorted()
        .iter()
        .map(|meta| meta.id.to_string())
        .collect();
    let documented: BTreeSet<String> = expectations.keys().cloned().collect();
    assert_eq!(
        registered, documented,
        "adversarial fixtures must cover exactly the registered rules; add \
fixtures/adversarial/<RULE-ID>/ and an expectations.toml entry for every new \
detector"
    );

    let mut failures = Vec::new();
    for meta in registry.metadata_sorted() {
        let expectation = &expectations[meta.id];
        assert!(
            !expectation.why.trim().is_empty(),
            "{}: explain the expected behaviour in `why`",
            meta.id
        );
        assert!(
            safe_relative(&expectation.file),
            "{}: fixture path must stay inside fixtures/adversarial: {}",
            meta.id,
            expectation.file
        );

        let path = base.join(&expectation.file);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: cannot read {}: {error}", meta.id, path.display()));
        let outcome = if path.extension().is_some_and(|ext| ext == "toml") {
            engine::scan_manifest_str("Cargo.toml", &source, &config, &registry)
                .unwrap_or_else(|error| panic!("{}: manifest fixture failed: {error}", meta.id))
        } else {
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("fixture.rs");
            engine::scan_source_str(&source, file_name, &config, &registry)
        };
        let hits: Vec<_> = outcome
            .findings
            .iter()
            .filter(|finding| finding.rule_id == meta.id)
            .collect();

        match expectation.expect.as_str() {
            "trigger" if hits.is_empty() => failures.push(format!(
                "{}: {} must trigger the rule but produced no finding. Expected: {}",
                meta.id, expectation.file, expectation.why
            )),
            "no-trigger" if !hits.is_empty() => failures.push(format!(
                "{}: {} must not trigger the rule but produced: {:?}. Expected: {}",
                meta.id,
                expectation.file,
                hits.iter()
                    .map(|finding| &finding.evidence)
                    .collect::<Vec<_>>(),
                expectation.why
            )),
            "trigger" | "no-trigger" => {}
            other => failures.push(format!(
                "{}: unknown expectation {other:?}; use \"trigger\" or \"no-trigger\"",
                meta.id
            )),
        }
    }

    assert!(
        failures.is_empty(),
        "adversarial fixture failures:\n{}",
        failures.join("\n")
    );
}
