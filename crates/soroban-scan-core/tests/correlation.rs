//! Related-findings correlation fixtures (#300).

use std::path::PathBuf;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::correlation::correlate;
use soroban_scan_core::engine;
use soroban_scan_core::finding::Finding;
use soroban_scan_core::registry::RuleRegistry;

fn fixture(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/correlation")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn scan(name: &str) -> Vec<Finding> {
    let source = fixture(name);
    let registry = RuleRegistry::with_default_rules();
    engine::scan_source_str(&source, name, &ScanConfig::default(), &registry).findings
}

fn find<'a>(findings: &'a [Finding], rule: &str, evidence: &str) -> &'a Finding {
    findings
        .iter()
        .find(|finding| finding.rule_id == rule && finding.evidence.contains(evidence))
        .unwrap_or_else(|| {
            panic!(
                "missing {rule} finding containing {evidence:?}; got: {:#?}",
                findings
                    .iter()
                    .map(|f| (f.rule_id.as_str(), f.evidence.as_str()))
                    .collect::<Vec<_>>()
            )
        })
}

#[test]
fn findings_on_the_same_construct_are_linked() {
    let findings = scan("related.rs");
    let auth = find(&findings, "SS-001", "bump");
    let arithmetic = find(&findings, "SS-008", "bump");

    let index = correlate(&findings);
    assert!(
        index
            .related_ids(&auth.fingerprint)
            .contains(&arithmetic.fingerprint),
        "the two rules flagging the same construct must be related"
    );
    assert!(index
        .related_ids(&arithmetic.fingerprint)
        .contains(&auth.fingerprint));
    assert!(!index.is_ambiguous(&auth.fingerprint));
    // Both findings remain present; correlation only adds links.
    assert!(findings.len() >= 2);
}

#[test]
fn unrelated_findings_are_not_linked() {
    let findings = scan("unrelated.rs");
    let auth = find(&findings, "SS-001", "store");
    let arithmetic = find(&findings, "SS-008", "add");

    let index = correlate(&findings);
    assert!(
        !index
            .related_ids(&auth.fingerprint)
            .contains(&arithmetic.fingerprint),
        "findings in different functions with different spans must not be linked"
    );
    assert!(!index
        .related_ids(&arithmetic.fingerprint)
        .contains(&auth.fingerprint));
}

#[test]
fn correlation_is_deterministic() {
    let findings = scan("related.rs");
    assert_eq!(correlate(&findings), correlate(&findings));
}
