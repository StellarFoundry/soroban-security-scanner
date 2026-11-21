//! False-negative guard (#138): every detector has a known-vulnerable sample
//! that must always trigger it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

#[derive(Debug, Deserialize)]
struct MustTrigger {
    file: String,
    why: String,
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_detector_has_a_must_trigger_sample() {
    let root = repository_root();
    let manifest_path = root.join("fixtures/must-trigger/manifest.toml");
    let manifest: BTreeMap<String, MustTrigger> =
        toml::from_str(&std::fs::read_to_string(&manifest_path).unwrap()).unwrap();
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();

    let registered: BTreeSet<String> = registry
        .metadata_sorted()
        .iter()
        .map(|meta| meta.id.to_string())
        .collect();
    let documented: BTreeSet<String> = manifest.keys().cloned().collect();
    assert_eq!(
        registered, documented,
        "every registered detector needs exactly one must-trigger entry"
    );

    for (rule_id, entry) in &manifest {
        assert!(
            !entry.why.trim().is_empty(),
            "{rule_id}: explain the true positive"
        );
        let path = root.join("fixtures/must-trigger").join(&entry.file);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{rule_id}: cannot read {}: {error}", path.display()));
        let outcome = if path
            .extension()
            .is_some_and(|extension| extension == "toml")
        {
            engine::scan_manifest_str("Cargo.toml", &source, &config, &registry)
                .unwrap_or_else(|error| panic!("{rule_id}: manifest fixture failed: {error}"))
        } else {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("must_trigger.rs");
            engine::scan_source_str(&source, name, &config, &registry)
        };
        assert!(
            outcome
                .findings
                .iter()
                .any(|finding| &finding.rule_id == rule_id),
            "{rule_id}: must-trigger sample {} did not trigger the rule",
            entry.file
        );
    }
}
