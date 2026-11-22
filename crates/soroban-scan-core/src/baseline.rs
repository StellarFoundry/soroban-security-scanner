//! Baselines: stable finding fingerprints for tracking new vs. known issues.
//!
//! A baseline records the fingerprints of accepted findings. Comparing a scan
//! against a baseline identifies findings that are new, already known, or
//! resolved. Fingerprints deliberately exclude line numbers so unrelated code
//! shifts do not resurrect known findings.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::error::ScanError;
use crate::finding::Finding;
use crate::model::{Diagnostic, DiagnosticCode};
use crate::registry::RuleRegistry;
use crate::severity::Severity;

/// Current baseline file format version.
pub const BASELINE_VERSION: u32 = 1;

/// Maximum accepted size of a baseline document, in bytes.
///
/// Baselines are untrusted input, so the document is bounded before parsing to
/// keep memory use predictable for very large or hostile files.
pub const MAX_BASELINE_BYTES: usize = 64 * 1024 * 1024;

/// Baseline artifact synchronization module.
pub mod sync {
    pub use crate::baseline_sync::*;
}

/// Marker written to TOML baselines.
pub const TOML_FORMAT_MARKER: &str = "soroban-scan-baseline";

/// A single baseline entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEntry {
    /// Stable finding fingerprint.
    pub fingerprint: String,
    /// Rule id.
    pub rule_id: String,
    /// Scan-root-relative file.
    pub file: String,
    /// Severity at the time the baseline was written.
    pub severity: Severity,
    /// Finding title.
    pub title: String,
}

/// A baseline document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Baseline {
    /// Format version.
    pub version: u32,
    /// Tool that produced the baseline.
    pub tool: String,
    /// Tool version that produced the baseline.
    pub tool_version: String,
    /// Optional format marker, present in TOML baselines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Accepted findings, sorted by fingerprint for determinism.
    pub findings: Vec<BaselineEntry>,
}

/// A reusable fingerprint index for repeated lookups against one baseline.
///
/// Comparison and other bulk operations build this once instead of rebuilding a
/// fresh fingerprint set for every finding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineIndex {
    fingerprints: BTreeSet<String>,
}

impl BaselineIndex {
    /// Builds an index from a baseline in a single pass.
    pub fn new(baseline: &Baseline) -> Self {
        BaselineIndex {
            fingerprints: baseline
                .findings
                .iter()
                .map(|entry| entry.fingerprint.clone())
                .collect(),
        }
    }

    /// Returns true when `fingerprint` is indexed.
    pub fn contains(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// Number of indexed fingerprints.
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// True when the baseline has no entries.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }
}

impl Baseline {
    /// Builds a baseline from current findings.
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut entries: Vec<BaselineEntry> = findings
            .iter()
            .map(|f| BaselineEntry {
                fingerprint: f.fingerprint.clone(),
                rule_id: f.rule_id.clone(),
                file: f.location.file.to_string_lossy().replace('\\', "/"),
                severity: f.severity,
                title: f.title.clone(),
            })
            .collect();
        entries.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);
        Baseline {
            version: BASELINE_VERSION,
            tool: crate::TOOL_NAME.to_string(),
            tool_version: crate::VERSION.to_string(),
            format: None,
            findings: entries,
        }
    }

    /// Fingerprint set for fast membership tests.
    pub fn fingerprints(&self) -> BTreeSet<&str> {
        self.findings
            .iter()
            .map(|entry| entry.fingerprint.as_str())
            .collect()
    }

    /// Builds a reusable fingerprint index.
    ///
    /// Bulk operations should build this once and reuse it rather than
    /// rebuilding a set for every lookup.
    pub fn index(&self) -> BaselineIndex {
        BaselineIndex::new(self)
    }

    /// Returns true if a finding is present in this baseline.
    ///
    /// This builds an index per call. Use [`Baseline::index`] for repeated
    /// lookups.
    pub fn contains(&self, finding: &Finding) -> bool {
        self.index().contains(finding.fingerprint.as_str())
    }

    /// Serializes the baseline to pretty JSON.
    pub fn to_json(&self) -> Result<String, ScanError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| ScanError::Baseline(format!("cannot serialize baseline: {e}")))
    }

    /// Parses a baseline from JSON.
    pub fn from_json(text: &str) -> Result<Self, ScanError> {
        if text.trim().is_empty() {
            return Err(ScanError::Baseline(
                "baseline JSON is empty; refusing to treat an empty file as a baseline".to_string(),
            ));
        }
        let baseline: Baseline = serde_json::from_str(text).map_err(|error| {
            let position = format!("line {}, column {}", error.line(), error.column());
            if error.is_eof() {
                ScanError::Baseline(format!(
                    "truncated baseline JSON at {position}: unexpected end of input; \
                     the file may have been partially written or interrupted"
                ))
            } else {
                ScanError::Baseline(format!("invalid baseline JSON at {position}: {error}"))
            }
        })?;
        baseline.validate_version()?;
        Ok(baseline)
    }

    /// Serializes the baseline to pretty TOML with a format marker.
    pub fn to_toml(&self) -> Result<String, ScanError> {
        let mut baseline = self.clone();
        baseline.format = Some(TOML_FORMAT_MARKER.to_string());
        toml::to_string_pretty(&baseline)
            .map_err(|e| ScanError::Baseline(format!("cannot serialize baseline TOML: {e}")))
    }

    /// Parses a baseline from TOML.
    pub fn from_toml(text: &str) -> Result<Self, ScanError> {
        if text.trim().is_empty() {
            return Err(ScanError::Baseline(
                "baseline TOML is empty; refusing to treat an empty file as a baseline".to_string(),
            ));
        }
        let baseline: Baseline = toml::from_str(text).map_err(|error| {
            let message = error.to_string();
            let lower = message.to_ascii_lowercase();
            if lower.contains("unexpected end") || lower.contains("eof") {
                ScanError::Baseline(format!(
                    "truncated baseline TOML: {message}; \
                     the file may have been partially written or interrupted"
                ))
            } else {
                ScanError::Baseline(format!("invalid baseline TOML: {message}"))
            }
        })?;
        baseline.validate_version()?;
        Ok(baseline)
    }

    /// Parses a baseline, detecting JSON or TOML from the content.
    pub fn from_text(text: &str) -> Result<Self, ScanError> {
        if text.len() > MAX_BASELINE_BYTES {
            return Err(ScanError::Baseline(format!(
                "baseline is too large ({} bytes; limit {} bytes)",
                text.len(),
                MAX_BASELINE_BYTES
            )));
        }
        if text.trim_start().starts_with('{') {
            Self::from_json(text)
        } else {
            Self::from_toml(text)
        }
    }

    fn validate_version(&self) -> Result<(), ScanError> {
        if self.version != BASELINE_VERSION {
            return Err(ScanError::Baseline(format!(
                "unsupported baseline version {} (expected {})",
                self.version, BASELINE_VERSION
            )));
        }
        Ok(())
    }

    /// Merges baselines by fingerprint in deterministic order.
    ///
    /// Entries are sorted by fingerprint and then severity before de-duplication,
    /// so the first entry kept for a fingerprint is stable across input order.
    pub fn merge(baselines: &[Baseline]) -> Self {
        let mut entries: Vec<BaselineEntry> = baselines
            .iter()
            .flat_map(|baseline| baseline.findings.iter().cloned())
            .collect();
        entries.sort_by(|a, b| {
            a.fingerprint
                .cmp(&b.fingerprint)
                .then_with(|| a.severity.cmp(&b.severity))
                .then_with(|| a.rule_id.cmp(&b.rule_id))
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.title.cmp(&b.title))
        });
        entries.dedup_by(|a, b| a.fingerprint == b.fingerprint);
        Baseline {
            version: BASELINE_VERSION,
            tool: crate::TOOL_NAME.to_string(),
            tool_version: crate::VERSION.to_string(),
            format: None,
            findings: entries,
        }
    }

    /// Removes entries that are no longer present in `findings`.
    ///
    /// Returns the pruned baseline and the number of removed entries.
    pub fn prune(&self, findings: &[Finding]) -> (Self, usize) {
        let current: BTreeSet<&str> = findings
            .iter()
            .map(|finding| finding.fingerprint.as_str())
            .collect();
        let before = self.findings.len();
        let mut entries: Vec<BaselineEntry> = self
            .findings
            .iter()
            .filter(|entry| current.contains(entry.fingerprint.as_str()))
            .cloned()
            .collect();
        entries.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let removed = before - entries.len();
        (
            Baseline {
                version: self.version,
                tool: self.tool.clone(),
                tool_version: self.tool_version.clone(),
                format: self.format.clone(),
                findings: entries,
            },
            removed,
        )
    }

    /// Diagnostics for baseline entries whose rule ids are no longer registered.
    ///
    /// Unknown ids are warnings: older baselines remain usable and forward
    /// compatible, but stale entries are surfaced to the user.
    pub fn unknown_rule_diagnostics(&self, registry: &RuleRegistry) -> Vec<Diagnostic> {
        let mut unknown: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &self.findings {
            if registry.by_id(&entry.rule_id).is_none() {
                *unknown.entry(entry.rule_id.as_str()).or_insert(0) += 1;
            }
        }
        unknown
            .into_iter()
            .map(|(rule_id, count)| {
                let suffix = if count == 1 {
                    String::new()
                } else {
                    format!(" ({count} entries)")
                };
                Diagnostic::warning(
                    DiagnosticCode::BaselineUnknownRule,
                    format!("baseline references unknown rule id `{rule_id}`{suffix}"),
                    None,
                )
            })
            .collect()
    }
}

/// Result of comparing findings against a baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    /// Indices (into the findings slice) of findings not in the baseline.
    pub new: Vec<usize>,
    /// Indices of findings already present in the baseline.
    pub existing: Vec<usize>,
    /// Baseline entries no longer present in the scan.
    pub resolved: Vec<BaselineEntry>,
}

impl Comparison {
    /// Number of new findings.
    pub fn new_count(&self) -> usize {
        self.new.len()
    }

    /// Number of existing (baselined) findings.
    pub fn existing_count(&self) -> usize {
        self.existing.len()
    }

    /// Number of resolved findings.
    pub fn resolved_count(&self) -> usize {
        self.resolved.len()
    }
}

/// Baseline state of a finding in machine-readable reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaselineStatus {
    /// The finding is not present in the baseline.
    New,
    /// The finding is already accepted by the baseline.
    Existing,
    /// A baseline entry no longer present in the scan.
    Resolved,
}

impl BaselineStatus {
    /// Stable lowercase name used in machine-readable reports.
    pub fn as_str(self) -> &'static str {
        match self {
            BaselineStatus::New => "new",
            BaselineStatus::Existing => "existing",
            BaselineStatus::Resolved => "resolved",
        }
    }
}

/// A resolved baseline entry included in machine-readable reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedFinding {
    /// Stable finding fingerprint.
    pub fingerprint: String,
    /// Rule id.
    pub rule_id: String,
    /// Scan-root-relative file.
    pub file: String,
    /// Severity at the time the baseline was written.
    pub severity: Severity,
    /// Finding title.
    pub title: String,
}

/// Baseline comparison summary for machine-readable reports.
///
/// The per-finding statuses are looked up by fingerprint and are not serialized
/// on their own: JSON findings carry `baseline_status` and SARIF results carry
/// `properties.baselineStatus`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BaselineReport {
    /// Number of findings not present in the baseline.
    pub new: usize,
    /// Number of findings already accepted by the baseline.
    pub existing: usize,
    /// Number of baseline entries no longer present in the scan.
    pub resolved: usize,
    /// Resolved entries; empty when the scan runs in incremental mode.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolved_findings: Vec<ResolvedFinding>,
    #[serde(skip)]
    statuses: BTreeMap<String, BaselineStatus>,
}

impl BaselineReport {
    /// Builds a report from a comparison.
    ///
    /// Set `include_resolved` to false for incremental scans, which do not
    /// treat missing findings as resolved.
    pub fn from_comparison(
        findings: &[Finding],
        comparison: &Comparison,
        include_resolved: bool,
    ) -> Self {
        let mut statuses = BTreeMap::new();
        for &index in &comparison.new {
            if let Some(finding) = findings.get(index) {
                statuses.insert(finding.fingerprint.clone(), BaselineStatus::New);
            }
        }
        for &index in &comparison.existing {
            if let Some(finding) = findings.get(index) {
                statuses.insert(finding.fingerprint.clone(), BaselineStatus::Existing);
            }
        }

        let resolved_findings = if include_resolved {
            comparison
                .resolved
                .iter()
                .map(|entry| ResolvedFinding {
                    fingerprint: entry.fingerprint.clone(),
                    rule_id: entry.rule_id.clone(),
                    file: entry.file.clone(),
                    severity: entry.severity,
                    title: entry.title.clone(),
                })
                .collect()
        } else {
            Vec::new()
        };

        BaselineReport {
            new: comparison.new_count(),
            existing: comparison.existing_count(),
            resolved: if include_resolved {
                comparison.resolved_count()
            } else {
                0
            },
            resolved_findings,
            statuses,
        }
    }

    /// Status of a finding, looked up by fingerprint.
    pub fn status(&self, fingerprint: &str) -> Option<BaselineStatus> {
        self.statuses.get(fingerprint).copied()
    }
}

/// Compares findings against a baseline by fingerprint.
///
/// The baseline index is built once and reused for every finding, so the pass
/// is linear in the number of findings plus baseline entries.
pub fn compare(findings: &[Finding], baseline: &Baseline) -> Comparison {
    let index = baseline.index();
    let mut current: BTreeSet<&str> = BTreeSet::new();

    let mut new = Vec::new();
    let mut existing = Vec::new();
    for (index_in_findings, finding) in findings.iter().enumerate() {
        current.insert(finding.fingerprint.as_str());
        if index.contains(finding.fingerprint.as_str()) {
            existing.push(index_in_findings);
        } else {
            new.push(index_in_findings);
        }
    }

    let resolved = baseline
        .findings
        .iter()
        .filter(|entry| !current.contains(entry.fingerprint.as_str()))
        .cloned()
        .collect();

    Comparison {
        new,
        existing,
        resolved,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::confidence::Confidence;
    use crate::finding::{Finding, SourceLocation};
    use crate::rule::RuleMetadata;

    fn meta() -> RuleMetadata {
        RuleMetadata::new(
            "SS-001",
            "Test",
            "test description long enough for validation purposes",
            Category::Authorization,
            Severity::High,
            Confidence::Medium,
            "fix",
        )
    }

    fn finding(file: &str, line: usize, evidence: &str) -> Finding {
        Finding::new(&meta(), SourceLocation::new(file, line), evidence)
    }

    #[test]
    fn baseline_round_trips_through_json() {
        let findings = vec![
            finding("src/lib.rs", 10, "a"),
            finding("src/lib.rs", 20, "b"),
        ];
        let baseline = Baseline::from_findings(&findings);
        let json = baseline.to_json().unwrap();
        let parsed = Baseline::from_json(&json).unwrap();
        assert_eq!(baseline, parsed);
        assert_eq!(parsed.findings.len(), 2);
    }

    #[test]
    fn toml_and_json_are_cross_compatible() {
        let findings = vec![finding("src/lib.rs", 10, "a")];
        let baseline = Baseline::from_findings(&findings);

        let json = baseline.to_json().unwrap();
        let toml = baseline.to_toml().unwrap();
        assert!(toml.contains("format = \"soroban-scan-baseline\""));

        assert_eq!(baseline, Baseline::from_json(&json).unwrap());
        let parsed_toml = Baseline::from_toml(&toml).unwrap();
        assert_eq!(parsed_toml.with_normalized_format(), baseline);
        let parsed_auto_json = Baseline::from_text(&json).unwrap();
        assert_eq!(parsed_auto_json, baseline);
        let parsed_auto_toml = Baseline::from_text(&toml).unwrap();
        assert_eq!(parsed_auto_toml.with_normalized_format(), baseline);
    }

    impl Baseline {
        fn with_normalized_format(mut self) -> Self {
            self.format = None;
            self
        }
    }

    fn entry(fingerprint: &str, severity: Severity) -> BaselineEntry {
        BaselineEntry {
            fingerprint: fingerprint.to_string(),
            rule_id: "SS-001".to_string(),
            file: "src/lib.rs".to_string(),
            severity,
            title: "Test".to_string(),
        }
    }

    #[test]
    fn merge_is_deterministic_and_deduplicates() {
        let a = Baseline {
            version: BASELINE_VERSION,
            tool: "soroban-scan".to_string(),
            tool_version: "0.1.0".to_string(),
            format: None,
            findings: vec![entry("b", Severity::High), entry("a", Severity::Low)],
        };
        let b = Baseline {
            version: BASELINE_VERSION,
            tool: "soroban-scan".to_string(),
            tool_version: "0.1.0".to_string(),
            format: None,
            findings: vec![entry("b", Severity::Medium), entry("c", Severity::High)],
        };
        let merged = Baseline::merge(&[a.clone(), b.clone()]);
        let merged_reversed = Baseline::merge(&[b, a]);
        assert_eq!(merged, merged_reversed);
        let fingerprints: Vec<_> = merged
            .findings
            .iter()
            .map(|entry| entry.fingerprint.as_str())
            .collect();
        assert_eq!(fingerprints, vec!["a", "b", "c"]);
        assert_eq!(merged.findings[1].severity, Severity::Medium);
    }

    #[test]
    fn prune_removes_resolved_entries() {
        let kept = finding("src/lib.rs", 10, "keep");
        let baseline = Baseline::from_findings(&[kept.clone(), finding("src/lib.rs", 20, "gone")]);
        let (pruned, removed) = baseline.prune(&[kept]);
        assert_eq!(removed, 1);
        assert_eq!(pruned.findings.len(), 1);
    }

    #[test]
    fn unknown_rule_ids_are_diagnostics() {
        let mut baseline = Baseline::from_findings(&[finding("src/lib.rs", 10, "a")]);
        baseline.findings[0].rule_id = "SS-999".to_string();
        let diagnostics = baseline.unknown_rule_diagnostics(&RuleRegistry::with_default_rules());
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, DiagnosticCode::BaselineUnknownRule);
        assert!(diagnostics[0].message.contains("SS-999"));
    }

    #[test]
    fn rejects_wrong_version() {
        let text = r#"{"version":99,"tool":"soroban-scan","tool_version":"0.1.0","findings":[]}"#;
        assert!(matches!(
            Baseline::from_json(text),
            Err(ScanError::Baseline(_))
        ));
    }

    #[test]
    fn comparison_identifies_new_and_resolved() {
        let old = finding("src/lib.rs", 10, "keep");
        let baseline = Baseline::from_findings(std::slice::from_ref(&old));

        let kept = finding("src/lib.rs", 999, "keep"); // line shift does not matter
        let fresh = finding("src/lib.rs", 20, "brand new");
        let findings = vec![kept, fresh];

        let comparison = compare(&findings, &baseline);
        assert_eq!(comparison.new_count(), 1);
        assert_eq!(comparison.existing_count(), 1);
        assert_eq!(comparison.resolved_count(), 0);
    }

    #[test]
    fn resolved_findings_are_reported() {
        let baseline = Baseline::from_findings(&[finding("src/lib.rs", 10, "gone")]);
        let comparison = compare(&[], &baseline);
        assert_eq!(comparison.resolved_count(), 1);
        assert_eq!(comparison.new_count(), 0);
    }

    #[test]
    fn baseline_output_is_deterministic() {
        let findings = vec![finding("b.rs", 1, "x"), finding("a.rs", 2, "y")];
        let first = Baseline::from_findings(&findings).to_json().unwrap();
        let second = Baseline::from_findings(&findings).to_json().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn truncated_json_is_rejected_with_position_and_truncation_hint() {
        let truncated = r#"{
  "version": 1,
  "tool": "soroban-scan",
  "tool_version": "0.2.0",
  "findings": [
    {"fingerprint": "abc""#;
        let error = Baseline::from_json(truncated).unwrap_err().to_string();

        assert!(error.contains("truncated baseline JSON"), "got: {error}");
        assert!(error.contains("line"), "got: {error}");
        assert!(error.contains("column"), "got: {error}");
        assert!(
            error.contains("partially written") || error.contains("interrupted"),
            "got: {error}"
        );
    }

    #[test]
    fn empty_baselines_are_rejected_not_treated_as_empty_baselines() {
        for (label, error) in [
            (
                "json",
                Baseline::from_json(" \n\t").unwrap_err().to_string(),
            ),
            ("toml", Baseline::from_toml("").unwrap_err().to_string()),
        ] {
            assert!(
                error.contains("empty"),
                "{label} baseline must be rejected as empty: {error}"
            );
        }
    }

    #[test]
    fn truncated_toml_is_rejected_clearly() {
        let truncated = "version = 1\ntool = \"soroban-scan\"\nfindings = [\n";
        let error = Baseline::from_toml(truncated).unwrap_err().to_string();
        assert!(error.contains("baseline TOML"), "got: {error}");
    }
    #[test]
    fn baseline_report_maps_new_existing_and_resolved() {
        let kept = finding("src/lib.rs", 10, "keep");
        let fresh = finding("src/lib.rs", 20, "fresh");
        let gone = finding("src/lib.rs", 30, "gone");

        let baseline = Baseline::from_findings(&[kept.clone(), gone.clone()]);
        let findings = vec![kept.clone(), fresh.clone()];
        let comparison = compare(&findings, &baseline);
        let report = BaselineReport::from_comparison(&findings, &comparison, true);

        assert_eq!(report.new, 1);
        assert_eq!(report.existing, 1);
        assert_eq!(report.resolved, 1);
        assert_eq!(report.resolved_findings.len(), 1);
        assert_eq!(report.resolved_findings[0].fingerprint, gone.fingerprint);
        assert_eq!(
            report.status(&kept.fingerprint),
            Some(BaselineStatus::Existing)
        );
        assert_eq!(report.status(&fresh.fingerprint), Some(BaselineStatus::New));
        assert_eq!(report.status(&gone.fingerprint), None);
    }

    #[test]
    fn incremental_baseline_report_does_not_count_resolved() {
        let kept = finding("src/lib.rs", 10, "keep");
        let gone = finding("src/lib.rs", 30, "gone");
        let baseline = Baseline::from_findings(&[kept.clone(), gone]);
        let findings = vec![kept];
        let comparison = compare(&findings, &baseline);
        let report = BaselineReport::from_comparison(&findings, &comparison, false);

        assert_eq!(report.resolved, 0);
        assert!(report.resolved_findings.is_empty());
    }

    #[test]
    fn reusable_index_answers_without_rebuilding() {
        let first = finding("src/lib.rs", 10, "a");
        let second = finding("src/lib.rs", 20, "b");
        let baseline = Baseline::from_findings(&[first.clone(), second.clone()]);
        let index = baseline.index();

        assert_eq!(index.len(), 2);
        assert!(!index.is_empty());
        assert!(index.contains(&first.fingerprint));
        assert!(index.contains(&second.fingerprint));
        assert!(!index.contains("missing"));
    }

    #[test]
    fn oversized_baselines_are_rejected_before_parsing() {
        let huge = " ".repeat(MAX_BASELINE_BYTES + 1);
        let error = Baseline::from_text(&huge).unwrap_err().to_string();
        assert!(error.contains("too large"), "got: {error}");
    }
}
