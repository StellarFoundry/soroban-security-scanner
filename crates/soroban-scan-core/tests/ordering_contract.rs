//! Finding ordering contract (#146).
//!
//! Consumers and snapshot tests rely on a stable order. The scanner sorts by
//! the tuple `(file, line, column, rule_id, fingerprint)`, and every renderer
//! must preserve that order.

use std::path::PathBuf;

use serde_json::Value;
use soroban_scan_core::category::Category;
use soroban_scan_core::confidence::Confidence;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine::{ScanOutcome, ScanStats};
use soroban_scan_core::finding::{Finding, SourceLocation};
use soroban_scan_core::model::{Project, ProjectKind, SorobanInfo};
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report::{self, OutputFormat};
use soroban_scan_core::severity::Severity;

/// Builds a finding with complete control over the ordering fields.
fn finding(
    rule_id: &str,
    file: &str,
    line: usize,
    column: Option<usize>,
    fingerprint: &str,
    evidence: &str,
) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        title: "Ordering fixture".to_string(),
        description: "A finding used to pin the deterministic ordering contract.".to_string(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        category: Category::Authorization,
        location: SourceLocation {
            file: PathBuf::from(file),
            line,
            column,
            end_line: None,
            end_column: None,
        },
        evidence: evidence.to_string(),
        remediation: "Apply the documented fix.".to_string(),
        references: vec![],
        fingerprint: fingerprint.to_string(),
    }
}

/// Mixed fixture exercising every sort-key tie-breaker.
fn mixed_findings() -> Vec<Finding> {
    vec![
        // Different file: sorts last.
        finding("SS-001", "src/b.rs", 1, Some(1), "eee", "marker-golf"),
        // Different line in the same file.
        finding("SS-001", "src/a.rs", 2, Some(1), "ddd", "marker-foxtrot"),
        // Same file/line, different column.
        finding("SS-002", "src/a.rs", 1, Some(2), "aaa", "marker-echo"),
        // Same file/line/column/rule: fingerprint tie-break (ccc after aaa).
        finding("SS-002", "src/a.rs", 1, Some(1), "ccc", "marker-delta"),
        // Same file/line/column: rule id tie-break (SS-001 before SS-002).
        finding("SS-001", "src/a.rs", 1, Some(1), "bbb", "marker-bravo"),
        // Same file/line/column/rule, smaller fingerprint.
        finding("SS-002", "src/a.rs", 1, Some(1), "aaa", "marker-charlie"),
        // Missing column sorts as 0, before every explicit column.
        finding("SS-001", "src/a.rs", 1, None, "ggg", "marker-alpha"),
    ]
}

fn sorted_findings() -> Vec<Finding> {
    let mut findings = mixed_findings();
    findings.sort_by_key(Finding::sort_key);
    findings
}

fn outcome_with(findings: Vec<Finding>) -> ScanOutcome {
    ScanOutcome {
        project: Project {
            root: PathBuf::from("."),
            kind: ProjectKind::GenericRust,
            manifests: vec![],
            soroban: SorobanInfo::default(),
            source_files: 1,
            diagnostics: vec![],
        },
        findings,
        diagnostics: vec![],
        stats: ScanStats::default(),
        config: ScanConfig::default(),
        suppressions: vec![],
        suppressed: vec![],
        truncation: None,
    }
}

fn evidence_order(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.evidence.as_str()).collect()
}

const EXPECTED_ORDER: [&str; 7] = [
    "marker-alpha",   // a.rs L1 column None -> 0
    "marker-bravo",   // a.rs L1 C1 SS-001
    "marker-charlie", // a.rs L1 C1 SS-002 fp aaa
    "marker-delta",   // a.rs L1 C1 SS-002 fp ccc
    "marker-echo",    // a.rs L1 C2
    "marker-foxtrot", // a.rs L2
    "marker-golf",    // b.rs L1
];

#[test]
fn sort_key_pins_every_component() {
    let f = finding("SS-007", "src/lib.rs", 9, Some(3), "abc123", "evidence");

    assert_eq!(
        f.sort_key(),
        (
            "src/lib.rs".to_string(),
            9,
            3,
            "SS-007".to_string(),
            "abc123".to_string()
        )
    );
}

#[test]
fn mixed_fixture_sorts_by_file_line_column_rule_then_fingerprint() {
    let sorted = sorted_findings();

    assert_eq!(evidence_order(&sorted), EXPECTED_ORDER.to_vec());
}

#[test]
fn terminal_renders_findings_in_contract_order() {
    let outcome = outcome_with(sorted_findings());
    let text = report::render_terminal(&outcome);

    let positions: Vec<_> = EXPECTED_ORDER
        .iter()
        .map(|evidence| text.find(evidence).expect("evidence is rendered"))
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "terminal order: {positions:?}"
    );
}

#[test]
fn json_renders_findings_in_contract_order() {
    let outcome = outcome_with(sorted_findings());
    let value: Value = serde_json::from_str(&report::render_json(&outcome).unwrap()).unwrap();
    let rendered: Vec<&str> = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["evidence"].as_str().unwrap())
        .collect();

    assert_eq!(rendered, EXPECTED_ORDER.to_vec());
}

#[test]
fn sarif_renders_findings_in_contract_order() {
    let registry = RuleRegistry::with_default_rules();
    let outcome = outcome_with(sorted_findings());
    let text = report::render_sarif(&outcome, &registry);
    let value: Value = serde_json::from_str(&text).unwrap();
    let rendered: Vec<&str> = value["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|result| {
            let message = result["message"]["text"].as_str().unwrap();
            EXPECTED_ORDER
                .iter()
                .copied()
                .find(|evidence| message.contains(evidence))
                .expect("SARIF message carries evidence")
        })
        .collect();

    assert_eq!(rendered, EXPECTED_ORDER.to_vec());
}

#[test]
fn markdown_renders_findings_in_contract_order() {
    let outcome = outcome_with(sorted_findings());
    let text = report::render_markdown(&outcome);

    let positions: Vec<_> = EXPECTED_ORDER
        .iter()
        .map(|evidence| text.find(evidence).expect("evidence is rendered"))
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "markdown order: {positions:?}"
    );
}

#[test]
fn every_format_receives_the_same_order() {
    let outcome = outcome_with(sorted_findings());
    let registry = RuleRegistry::with_default_rules();

    // `render` dispatches to the same renderers; this guards against a future
    // format being added without preserving the contract.
    for format in [
        OutputFormat::Terminal,
        OutputFormat::Json,
        OutputFormat::Sarif,
        OutputFormat::Markdown,
    ] {
        let text = report::render(&outcome, &registry, format);
        let first = text.find("marker-alpha").expect("first finding");
        let last = text.find("marker-golf").expect("last finding");
        assert!(first < last, "{} reversed the order", format.as_str());
    }
}
