//! Snapshot for conservative root-cause grouping (#301).
//!
//! `fixtures/correlation/related.rs` produces one group; `unrelated.rs` produces
//! singletons only. Update with:
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test grouping
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::correlation;
use soroban_scan_core::engine;
use soroban_scan_core::finding::Finding;
use soroban_scan_core::registry::RuleRegistry;

#[derive(Debug, Serialize)]
struct GroupSnapshot {
    id: String,
    explanation: String,
    rule_ids: Vec<String>,
    fingerprints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SingletonSnapshot {
    rule_id: String,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct FileSnapshot {
    groups: Vec<GroupSnapshot>,
    singletons: Vec<SingletonSnapshot>,
}

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/correlation")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn scan(name: &str) -> Vec<Finding> {
    let source = fixture(name);
    engine::scan_source_str(
        &source,
        name,
        &ScanConfig::default(),
        &RuleRegistry::with_default_rules(),
    )
    .findings
}

fn snapshot(name: &str) -> FileSnapshot {
    let findings = scan(name);
    let index = correlation::group(&findings);
    let groups = index
        .groups()
        .iter()
        .map(|group| GroupSnapshot {
            id: group.id.clone(),
            explanation: group.explanation.clone(),
            rule_ids: group.rule_ids.clone(),
            fingerprints: group.fingerprints.clone(),
        })
        .collect();
    let mut singletons: Vec<SingletonSnapshot> = findings
        .iter()
        .filter(|finding| index.group_of(&finding.fingerprint).is_none())
        .map(|finding| SingletonSnapshot {
            rule_id: finding.rule_id.clone(),
            fingerprint: finding.fingerprint.clone(),
        })
        .collect();
    singletons.sort_by(|a, b| {
        (a.rule_id.as_str(), a.fingerprint.as_str())
            .cmp(&(b.rule_id.as_str(), b.fingerprint.as_str()))
    });
    FileSnapshot { groups, singletons }
}

#[test]
fn finding_groups_match_snapshot() {
    let mut result = BTreeMap::new();
    result.insert("related", snapshot("related.rs"));
    result.insert("unrelated", snapshot("unrelated.rs"));

    let actual = serde_json::to_string_pretty(&result).expect("serialize grouping snapshot");
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/finding_groups.json");
    let actual = format!("{actual}\n");
    if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().expect("snapshot directory"))
            .expect("create snapshot directory");
        std::fs::write(&path, actual.as_bytes()).expect("write grouping snapshot");
        return;
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing grouping snapshot {}: {error}\n\
             Generate it with UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test grouping",
            path.display()
        )
    });
    assert_eq!(
        expected.replace("\r\n", "\n"),
        actual,
        "grouping snapshot changed; review it and update with UPDATE_SNAPSHOTS=1"
    );
}
