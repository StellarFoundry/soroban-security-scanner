//! End-to-end taint regression fixtures (#287).
//!
//! `tests/taint_auth.rs`, `tests/taint_amounts.rs`, and
//! `tests/taint_addresses.rs` assert the flow API itself. This test scans the
//! same fixtures through the full engine and pins the resulting finding ids and
//! confidence levels, so a propagation or rule regression changes a reviewable
//! snapshot instead of passing silently.
//!
//! The fixtures are offline and deterministic. Update the snapshot only for an
//! intentional behaviour change:
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test taint_findings
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

/// Fixtures covering direct, helper-mediated, transformed, and sanitized flows.
const FIXTURES: &[&str] = &[
    "auth_direct.rs",
    "auth_helper.rs",
    "auth_sanitized.rs",
    "amount_direct.rs",
    "amount_arithmetic.rs",
    "amount_validated.rs",
    "address_direct.rs",
    "address_decoded.rs",
    "address_validated.rs",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExpectedFinding {
    rule_id: String,
    severity: String,
    confidence: String,
    count: usize,
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/taint")
}

fn snapshot_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/taint_findings.json")
}

fn fixture_findings() -> BTreeMap<String, Vec<ExpectedFinding>> {
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let dir = fixtures_dir();
    let mut result = BTreeMap::new();

    for name in FIXTURES {
        let path = dir.join(name);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let outcome = engine::scan_source_str(source.as_str(), name, &config, &registry);

        let mut counts: BTreeMap<(String, String, String), usize> = BTreeMap::new();
        for finding in outcome.findings {
            *counts
                .entry((
                    finding.rule_id,
                    finding.severity.as_str().to_string(),
                    finding.confidence.as_str().to_string(),
                ))
                .or_insert(0) += 1;
        }
        let findings = counts
            .into_iter()
            .map(|((rule_id, severity, confidence), count)| ExpectedFinding {
                rule_id,
                severity,
                confidence,
                count,
            })
            .collect();
        result.insert((*name).to_string(), findings);
    }
    result
}

fn render(findings: &BTreeMap<String, Vec<ExpectedFinding>>) -> String {
    let mut text = serde_json::to_string_pretty(findings).expect("serialize taint findings");
    text.push('\n');
    text
}

#[test]
fn taint_fixture_findings_match_snapshot() {
    let actual = render(&fixture_findings());
    let path = snapshot_path();

    if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().expect("snapshot directory"))
            .expect("create snapshot directory");
        std::fs::write(&path, actual.as_bytes())
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing taint snapshot {}: {error}\n\
             Generate it with UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test taint_findings",
            path.display()
        )
    });
    let expected = expected.replace("\r\n", "\n");
    assert!(
        expected == actual,
        "taint fixture findings changed.\nReview the diff, then update with \
         UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test taint_findings"
    );
}

#[test]
fn taint_findings_are_stable_across_runs() {
    assert_eq!(render(&fixture_findings()), render(&fixture_findings()));
}

#[test]
fn amount_validation_removes_the_unchecked_transfer_finding() {
    let findings = fixture_findings();
    let rule_ids = |name: &str| -> Vec<String> {
        findings[name]
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect()
    };
    assert!(
        rule_ids("amount_direct.rs").iter().any(|id| id == "SS-014"),
        "direct amount fixture must trigger SS-014"
    );
    assert!(
        !rule_ids("amount_validated.rs")
            .iter()
            .any(|id| id == "SS-014"),
        "a documented sanitizer must clear the unchecked-amount finding"
    );
}
