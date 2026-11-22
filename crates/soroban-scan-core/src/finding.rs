//! The finding model: everything the scanner reports about a security issue.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::cfg::Reachability;
use crate::category::Category;
use crate::confidence::Confidence;
use crate::rule::RuleMetadata;
use crate::severity::Severity;

/// A precise location in the scanned source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceLocation {
    /// Source file, relative to the scan root where possible.
    ///
    /// Serialized with forward slashes so machine-readable output is identical
    /// across operating systems.
    #[serde(serialize_with = "serialize_path")]
    pub file: PathBuf,
    /// 1-based line number.
    pub line: usize,
    /// 1-based column number, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    /// 1-based end line, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<usize>,
    /// 1-based end column, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<usize>,
}

impl SourceLocation {
    /// Creates a location from a file and line.
    pub fn new(file: impl Into<PathBuf>, line: usize) -> Self {
        SourceLocation {
            file: file.into(),
            line,
            column: None,
            end_line: None,
            end_column: None,
        }
    }

    /// Creates a location with a column.
    pub fn with_column(file: impl Into<PathBuf>, line: usize, column: usize) -> Self {
        SourceLocation {
            file: file.into(),
            line,
            column: Some(column),
            end_line: None,
            end_column: None,
        }
    }

    /// Sets the end position.
    pub fn with_end(mut self, end_line: usize, end_column: Option<usize>) -> Self {
        self.end_line = Some(end_line);
        self.end_column = end_column;
        self
    }

    /// Human-readable `file:line` (and `:column`) label.
    pub fn display_label(&self) -> String {
        match self.column {
            Some(col) => format!("{}:{}:{}", self.file.display(), self.line, col),
            None => format!("{}:{}", self.file.display(), self.line),
        }
    }
}

/// A single security finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier (for example `SS-001`).
    pub rule_id: String,
    /// Short title.
    pub title: String,
    /// Longer description of the issue.
    pub description: String,
    /// Impact severity.
    pub severity: Severity,
    /// Detection confidence.
    pub confidence: Confidence,
    /// Category.
    pub category: Category,
    /// Source location.
    pub location: SourceLocation,
    /// Concrete evidence from the source.
    pub evidence: String,
    /// Remediation guidance.
    pub remediation: String,
    /// External references.
    pub references: Vec<String>,
    /// Stable fingerprint used for baselines.
    pub fingerprint: String,
    /// Reachability of the reported line, used only to rank output.
    ///
    /// This is a scanner-internal annotation: it is never serialized and does
    /// not change detection. Reports loaded from JSON keep `Unknown`.
    #[serde(skip)]
    pub reachability: Reachability,
}

impl Finding {
    /// Creates a finding using a rule's metadata defaults.
    pub fn new(meta: &RuleMetadata, location: SourceLocation, evidence: impl Into<String>) -> Self {
        let evidence = evidence.into();
        let fingerprint = fingerprint_of(meta.id, &location.file, &evidence);
        Finding {
            rule_id: meta.id.to_string(),
            title: meta.title.to_string(),
            description: meta.description.to_string(),
            severity: meta.default_severity,
            confidence: meta.default_confidence,
            category: meta.category,
            location,
            evidence,
            remediation: meta.remediation.to_string(),
            references: meta.references.iter().map(|r| (*r).to_string()).collect(),
            fingerprint,
            reachability: Reachability::Unknown,
        }
    }

    /// Recomputes the fingerprint (after mutating location/evidence).
    pub fn refresh_fingerprint(&mut self) {
        self.refresh_fingerprint_with(crate::fingerprint::FingerprintStrategy::default());
    }

    /// Recomputes the fingerprint using an explicit strategy.
    pub fn refresh_fingerprint_with(&mut self, strategy: crate::fingerprint::FingerprintStrategy) {
        self.fingerprint = strategy.compute(
            &self.rule_id,
            &self.location.file,
            self.location.line,
            self.location.column,
            &self.evidence,
        );
    }

    /// Deterministic ranking key: severity, confidence, reachability, then span.
    ///
    /// Severity and confidence are compared highest first, reachability puts
    /// reachable code before unknown and unreachable code, and the remaining
    /// components (`file, line, column, rule id, fingerprint`) keep the order
    /// unique and stable. Ranking only changes order; it never removes a
    /// finding.
    pub fn sort_key(&self) -> (u8, u8, u8, String, usize, usize, String, String) {
        (
            u8::MAX - self.severity.rank(),
            u8::MAX - self.confidence.rank(),
            u8::MAX - self.reachability.rank(),
            self.location.file.to_string_lossy().replace('\\', "/"),
            self.location.line,
            self.location.column.unwrap_or(0),
            self.rule_id.clone(),
            self.fingerprint.clone(),
        )
    }

    /// Identity used for exact de-duplication.
    pub fn identity(&self) -> (String, String, usize, usize, String) {
        (
            self.rule_id.clone(),
            self.location.file.to_string_lossy().replace('\\', "/"),
            self.location.line,
            self.location.column.unwrap_or(0),
            normalize_evidence(&self.evidence),
        )
    }
}

/// Serializes a path with forward slashes for stable cross-platform output.
fn serialize_path<S>(path: &Path, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&path.to_string_lossy().replace('\\', "/"))
}

/// Normalizes evidence text so fingerprints are whitespace-insensitive.
pub fn normalize_evidence(evidence: &str) -> String {
    evidence.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Computes a stable fingerprint for a rule/file/evidence triple.
///
/// The line number is intentionally excluded so that findings survive
/// unrelated line shifts (important for baselines).
pub fn fingerprint_of(rule_id: &str, file: &Path, evidence: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(file.to_string_lossy().replace('\\', "/").as_bytes());
    hasher.update(b"\0");
    hasher.update(normalize_evidence(evidence).as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_whitespace_insensitive() {
        let a = fingerprint_of(
            "SS-001",
            Path::new("src/lib.rs"),
            "  require_auth\n missing ",
        );
        let b = fingerprint_of("SS-001", Path::new("src/lib.rs"), "require_auth missing");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn fingerprint_changes_with_rule_and_file() {
        let base = fingerprint_of("SS-001", Path::new("src/lib.rs"), "x");
        assert_ne!(base, fingerprint_of("SS-002", Path::new("src/lib.rs"), "x"));
        assert_ne!(base, fingerprint_of("SS-001", Path::new("src/a.rs"), "x"));
    }

    #[test]
    fn location_label_includes_column() {
        let loc = SourceLocation::with_column("src/lib.rs", 10, 5);
        assert_eq!(loc.display_label(), "src/lib.rs:10:5");
        let loc = SourceLocation::new("src/lib.rs", 10);
        assert_eq!(loc.display_label(), "src/lib.rs:10");
    }

    #[test]
    fn paths_serialize_with_forward_slashes() {
        let loc = SourceLocation::new("src\\nested\\lib.rs", 1);
        let json = serde_json::to_string(&loc).unwrap();
        assert!(json.contains("src/nested/lib.rs"), "got: {json}");
        assert!(!json.contains('\\'), "got: {json}");
    }
}
