//! Comparison of two JSON scan reports.
//!
//! Findings are matched by their stable fingerprint (rule id, scan-relative
//! file, and normalized evidence), the same identity used by baselines. A
//! finding whose fingerprint changed is paired with the same rule id and file
//! and reported as *renamed* instead of being silently dropped.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;

use serde_json::Value;

use crate::finding::Finding;
use crate::report::REPORT_SCHEMA_VERSION;

/// Maximum accepted size of one JSON report, in bytes.
///
/// Reports are untrusted input; the document is bounded before parsing so a
/// hostile or truncated file cannot force unbounded memory use.
pub const MAX_REPORT_BYTES: usize = 64 * 1024 * 1024;

/// Maximum number of findings accepted from one report.
pub const MAX_COMPARISON_FINDINGS: usize = 100_000;

/// Reason a report could not be used for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareError {
    /// The document exceeds [`MAX_REPORT_BYTES`].
    TooLarge(usize),
    /// The document is empty or whitespace-only.
    Empty,
    /// The document is not valid JSON or is missing required fields.
    Invalid(String),
    /// The report was produced by an incompatible schema version.
    UnsupportedSchema(String),
    /// The document contains more than [`MAX_COMPARISON_FINDINGS`] findings.
    TooManyFindings(usize),
}

impl fmt::Display for CompareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompareError::TooLarge(bytes) => f.write_str(&format!(
                "report is too large ({bytes} bytes; limit {MAX_REPORT_BYTES} bytes)"
            )),
            CompareError::Empty => f.write_str("report JSON is empty"),
            CompareError::Invalid(message) => {
                f.write_str(&format!("invalid report JSON: {message}"))
            }
            CompareError::UnsupportedSchema(version) => f.write_str(&format!(
                "unsupported report schema version `{version}` (expected {REPORT_SCHEMA_VERSION})"
            )),
            CompareError::TooManyFindings(count) => f.write_str(&format!(
                "report contains too many findings ({count}; limit {MAX_COMPARISON_FINDINGS})"
            )),
        }
    }
}

impl std::error::Error for CompareError {}

/// The parts of a scan report needed to compare two runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Competing report contract version.
    pub schema_version: String,
    /// Project root recorded by the scan, when present.
    pub project_root: Option<String>,
    /// Findings, in report order.
    pub findings: Vec<Finding>,
}

/// Parses the findings and summary fields from a JSON scan report.
///
/// The full report is not deserialized into a typed struct: only the fields
/// needed for comparison are read, so additive report changes stay compatible.
pub fn parse_report(text: &str) -> Result<ScanReport, CompareError> {
    if text.len() > MAX_REPORT_BYTES {
        return Err(CompareError::TooLarge(text.len()));
    }
    if text.trim().is_empty() {
        return Err(CompareError::Empty);
    }
    let value: Value =
        serde_json::from_str(text).map_err(|error| CompareError::Invalid(error.to_string()))?;

    let schema_version = value
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if schema_version != REPORT_SCHEMA_VERSION {
        return Err(CompareError::UnsupportedSchema(
            if schema_version.is_empty() {
                "missing".to_string()
            } else {
                schema_version
            },
        ));
    }

    let findings_value = value
        .get("findings")
        .ok_or_else(|| CompareError::Invalid("report has no findings array".to_string()))?;
    let findings_array = findings_value
        .as_array()
        .ok_or_else(|| CompareError::Invalid("report findings is not an array".to_string()))?;
    if findings_array.len() > MAX_COMPARISON_FINDINGS {
        return Err(CompareError::TooManyFindings(findings_array.len()));
    }
    let findings: Vec<Finding> = serde_json::from_value(Value::Array(findings_array.clone()))
        .map_err(|error| CompareError::Invalid(format!("invalid finding: {error}")))?;

    let project_root = value
        .get("project")
        .and_then(|project| project.get("root"))
        .and_then(Value::as_str)
        .map(str::to_string);

    Ok(ScanReport {
        schema_version,
        project_root,
        findings,
    })
}

/// A finding that kept its rule id and file but changed fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FindingChange {
    /// Finding from the older report.
    pub before: Finding,
    /// Finding from the newer report.
    pub after: Finding,
}

/// The result of comparing two scan reports.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Comparison {
    /// Findings present in both reports with the same fingerprint.
    pub unchanged: Vec<Finding>,
    /// Findings only in the newer report, with no same-rule/file predecessor.
    pub new: Vec<Finding>,
    /// Findings only in the older report, with no same-rule/file successor.
    pub fixed: Vec<Finding>,
    /// Findings that kept their rule id and file but changed fingerprint.
    pub renamed: Vec<FindingChange>,
}

impl Comparison {
    /// Number of unchanged findings.
    pub fn unchanged_count(&self) -> usize {
        self.unchanged.len()
    }

    /// Number of new findings.
    pub fn new_count(&self) -> usize {
        self.new.len()
    }

    /// Number of fixed findings.
    pub fn fixed_count(&self) -> usize {
        self.fixed.len()
    }

    /// Number of renamed (fingerprint-changed) findings.
    pub fn renamed_count(&self) -> usize {
        self.renamed.len()
    }
}

fn sorted(findings: &[Finding]) -> Vec<Finding> {
    let mut findings = findings.to_vec();
    findings.sort_by_key(Finding::sort_key);
    findings
}

fn file_key(finding: &Finding) -> (String, String) {
    (
        finding.rule_id.clone(),
        finding.location.file.to_string_lossy().replace('\\', "/"),
    )
}

/// Compares two reports by fingerprint.
///
/// Duplicate fingerprints are matched one-for-one, so a report containing the
/// same fingerprint at two lines does not hide the second occurrence.
pub fn compare_reports(before: &ScanReport, after: &ScanReport) -> Comparison {
    let before_findings = sorted(&before.findings);
    let after_findings = sorted(&after.findings);

    let mut after_by_fingerprint: BTreeMap<&str, VecDeque<usize>> = BTreeMap::new();
    for (index, finding) in after_findings.iter().enumerate() {
        after_by_fingerprint
            .entry(finding.fingerprint.as_str())
            .or_default()
            .push_back(index);
    }

    let mut consumed_after = vec![false; after_findings.len()];
    let mut unchanged = Vec::new();
    let mut before_only = Vec::new();
    for finding in before_findings {
        match after_by_fingerprint
            .get_mut(finding.fingerprint.as_str())
            .and_then(VecDeque::pop_front)
        {
            Some(index) => {
                consumed_after[index] = true;
                unchanged.push(after_findings[index].clone());
            }
            None => before_only.push(finding),
        }
    }

    let after_only: Vec<usize> = (0..after_findings.len())
        .filter(|index| !consumed_after[*index])
        .collect();

    // Pair remaining findings by rule id and file. This is the only stable
    // signal left once the evidence changed; it is reported explicitly as a
    // rename, never as a silent fix or new finding.
    let mut after_by_key: BTreeMap<(String, String), VecDeque<usize>> = BTreeMap::new();
    for &index in &after_only {
        after_by_key
            .entry(file_key(&after_findings[index]))
            .or_default()
            .push_back(index);
    }

    let mut renamed = Vec::new();
    let mut fixed = Vec::new();
    let mut claimed_after: BTreeMap<usize, bool> = BTreeMap::new();
    for finding in before_only {
        let key = file_key(&finding);
        match after_by_key.get_mut(&key).and_then(VecDeque::pop_front) {
            Some(index) => {
                claimed_after.insert(index, true);
                renamed.push(FindingChange {
                    before: finding,
                    after: after_findings[index].clone(),
                });
            }
            None => fixed.push(finding),
        }
    }

    let new = after_only
        .into_iter()
        .filter(|index| !claimed_after.contains_key(index))
        .map(|index| after_findings[index].clone())
        .collect();

    Comparison {
        unchanged,
        new,
        fixed,
        renamed,
    }
}

/// A compact, single-line description of a finding.
fn finding_summary(finding: &Finding) -> String {
    let evidence = finding
        .evidence
        .lines()
        .next()
        .unwrap_or_default()
        .chars()
        .take(120)
        .collect::<String>();
    format!(
        "[{}] {} {} — {}\n    fingerprint: {}\n    evidence: {}",
        finding.severity.as_str(),
        finding.rule_id,
        finding.location.display_label(),
        finding.title,
        finding.fingerprint,
        evidence
    )
}

/// Renders a comparison as human-readable text, including every finding.
pub fn render_comparison_text(
    before: &ScanReport,
    after: &ScanReport,
    comparison: &Comparison,
) -> String {
    let mut out = String::new();
    out.push_str("Report comparison\n");
    out.push_str(&format!(
        "Before: {} ({} finding(s))\n",
        before
            .project_root
            .as_deref()
            .unwrap_or("(unknown project)"),
        before.findings.len()
    ));
    out.push_str(&format!(
        "After:  {} ({} finding(s))\n\n",
        after.project_root.as_deref().unwrap_or("(unknown project)"),
        after.findings.len()
    ));
    out.push_str(&format!(
        "Unchanged: {}  New: {}  Fixed: {}  Renamed: {}\n",
        comparison.unchanged_count(),
        comparison.new_count(),
        comparison.fixed_count(),
        comparison.renamed_count()
    ));
    out.push_str(
        "\nMatching uses the documented fingerprint (rule id, file, normalized evidence).\n\
         Renamed findings keep the same rule id and file but changed fingerprint.\n",
    );

    if !comparison.new.is_empty() {
        out.push_str(&format!("\nNew findings ({}):\n", comparison.new.len()));
        for finding in &comparison.new {
            out.push_str(&format!("  {}\n", finding_summary(finding)));
        }
    }
    if !comparison.fixed.is_empty() {
        out.push_str(&format!("\nFixed findings ({}):\n", comparison.fixed.len()));
        for finding in &comparison.fixed {
            out.push_str(&format!("  {}\n", finding_summary(finding)));
        }
    }
    if !comparison.renamed.is_empty() {
        out.push_str(&format!(
            "\nRenamed findings ({}):\n\
             These entries are unmatched by fingerprint but share a rule id and file.\n",
            comparison.renamed.len()
        ));
        for change in &comparison.renamed {
            out.push_str(&format!(
                "  before: {}\n  after:  {}\n\n",
                finding_summary(&change.before),
                finding_summary(&change.after)
            ));
        }
    }
    if !comparison.unchanged.is_empty() {
        out.push_str(&format!(
            "Unchanged findings ({}):\n",
            comparison.unchanged.len()
        ));
        for finding in &comparison.unchanged {
            out.push_str(&format!("  {}\n", finding_summary(finding)));
        }
    }
    if comparison.new.is_empty()
        && comparison.fixed.is_empty()
        && comparison.renamed.is_empty()
        && comparison.unchanged.is_empty()
    {
        out.push_str("\nNo findings in either report.\n");
    }
    out
}

/// Renders a comparison as JSON, including every finding.
pub fn render_comparison_json(
    before: &ScanReport,
    after: &ScanReport,
    comparison: &Comparison,
) -> Result<String, serde_json::Error> {
    let document = serde_json::json!({
        "comparison_version": "1",
        "before": {
            "schema_version": before.schema_version,
            "project_root": before.project_root,
            "findings": before.findings.len(),
        },
        "after": {
            "schema_version": after.schema_version,
            "project_root": after.project_root,
            "findings": after.findings.len(),
        },
        "summary": {
            "unchanged": comparison.unchanged_count(),
            "new": comparison.new_count(),
            "fixed": comparison.fixed_count(),
            "renamed": comparison.renamed_count(),
        },
        "unchanged": comparison.unchanged,
        "new": comparison.new,
        "fixed": comparison.fixed,
        "renamed": comparison.renamed,
        "notes": [
            "Findings are matched by the documented fingerprint: rule id, scan-relative file, and normalized evidence.",
            "Renamed findings share a rule id and file with a finding in the other report but have a different fingerprint, so they are neither new nor fixed.",
        ],
    });
    serde_json::to_string_pretty(&document)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixtures() -> (ScanReport, ScanReport) {
        let before = include_str!("../../../fixtures/reports/comparison-before.json");
        let after = include_str!("../../../fixtures/reports/comparison-after.json");
        (
            parse_report(before).expect("before fixture must parse"),
            parse_report(after).expect("after fixture must parse"),
        )
    }

    #[test]
    fn fixtures_report_unchanged_new_fixed_and_renamed() {
        let (before, after) = fixtures();
        let comparison = compare_reports(&before, &after);

        assert_eq!(comparison.unchanged_count(), 1);
        assert_eq!(comparison.fixed_count(), 2);
        assert_eq!(comparison.new_count(), 1);
        assert_eq!(comparison.renamed_count(), 1);
        assert_eq!(comparison.renamed[0].before.rule_id, "SS-001");
        assert_eq!(
            comparison.renamed[0].before.location.file,
            comparison.renamed[0].after.location.file
        );
        assert_ne!(
            comparison.renamed[0].before.fingerprint,
            comparison.renamed[0].after.fingerprint
        );
    }

    #[test]
    fn text_output_lists_the_findings_not_only_counts() {
        let (before, after) = fixtures();
        let comparison = compare_reports(&before, &after);
        let text = render_comparison_text(&before, &after, &comparison);

        assert!(text.contains("Unchanged: 1  New: 1  Fixed: 2  Renamed: 1"));
        assert!(text.contains("src/lib.rs"));
        assert!(text.contains("src/admin.rs"));
        assert!(text.contains("fingerprint:"));
        assert!(text.contains("New findings (1)"));
        assert!(text.contains("Fixed findings (2)"));
        assert!(text.contains("Renamed findings (1)"));
    }

    #[test]
    fn json_output_contains_full_findings() {
        let (before, after) = fixtures();
        let comparison = compare_reports(&before, &after);
        let json = render_comparison_json(&before, &after, &comparison).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["summary"]["unchanged"], 1);
        assert_eq!(value["summary"]["new"], 1);
        assert_eq!(value["summary"]["fixed"], 2);
        assert_eq!(value["summary"]["renamed"], 1);
        assert!(value["new"][0]["evidence"].is_string());
        assert!(value["renamed"][0]["before"]["fingerprint"].is_string());
    }

    #[test]
    fn comparison_is_independent_of_report_order() {
        let (before, mut after) = fixtures();
        after.findings.reverse();
        let comparison = compare_reports(&before, &after);
        assert_eq!(comparison.unchanged_count(), 1);
        assert_eq!(comparison.fixed_count(), 2);
        assert_eq!(comparison.new_count(), 1);
        assert_eq!(comparison.renamed_count(), 1);
    }

    #[test]
    fn empty_and_malformed_reports_are_rejected() {
        assert_eq!(parse_report("  "), Err(CompareError::Empty));
        assert!(matches!(parse_report("{"), Err(CompareError::Invalid(_))));
        assert!(matches!(
            parse_report(r#"{"schema_version":"99","findings":[]}"#),
            Err(CompareError::UnsupportedSchema(_))
        ));
        assert!(matches!(
            parse_report(r#"{"schema_version":"1"}"#),
            Err(CompareError::Invalid(_))
        ));
    }

    #[test]
    fn oversized_reports_are_rejected_before_parsing() {
        let huge = " ".repeat(MAX_REPORT_BYTES + 1);
        assert_eq!(parse_report(&huge), Err(CompareError::TooLarge(huge.len())));
    }
}
