//! The finding model: everything the scanner reports about a security issue.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::rule::RuleMetadata;
use crate::severity::Severity;

/// Strategy used to compute finding fingerprints for baseline matching.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FingerprintStrategy {
    /// Default strategy: hashes `(rule_id, file, normalized_evidence)`.
    #[default]
    #[serde(alias = "file_relative")]
    FileRelative,
    /// Hashes `(rule_id, file, function_scope, normalized_evidence)`.
    #[serde(alias = "function_scoped")]
    FunctionScoped,
    /// Hashes `(rule_id, normalized_evidence)` independent of the file path.
    #[serde(alias = "content_hash")]
    ContentHash,
}

impl FingerprintStrategy {
    /// Returns true when the strategy is the default (`FileRelative`).
    pub fn is_default(&self) -> bool {
        matches!(self, FingerprintStrategy::FileRelative)
    }

    /// Stable lowercase identifier.
    pub fn as_str(self) -> &'static str {
        match self {
            FingerprintStrategy::FileRelative => "file-relative",
            FingerprintStrategy::FunctionScoped => "function-scoped",
            FingerprintStrategy::ContentHash => "content-hash",
        }
    }
}

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
        }
    }

    /// Recomputes the fingerprint (after mutating location/evidence).
    pub fn refresh_fingerprint(&mut self) {
        self.fingerprint = fingerprint_of(&self.rule_id, &self.location.file, &self.evidence);
    }

    /// Recomputes the fingerprint using the configured [`FingerprintStrategy`].
    pub fn refresh_fingerprint_with(
        &mut self,
        strategy: FingerprintStrategy,
        function_scope: Option<&str>,
    ) {
        self.fingerprint = fingerprint_with_strategy(
            strategy,
            &self.rule_id,
            &self.location.file,
            function_scope,
            &self.evidence,
        );
    }

    /// Deterministic sort key: file, line, column, rule id, fingerprint.
    pub fn sort_key(&self) -> (String, usize, usize, String, String) {
        (
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

/// Computes a finding fingerprint using the given [`FingerprintStrategy`].
pub fn fingerprint_with_strategy(
    strategy: FingerprintStrategy,
    rule_id: &str,
    file: &Path,
    function_scope: Option<&str>,
    evidence: &str,
) -> String {
    match strategy {
        FingerprintStrategy::FileRelative => fingerprint_of(rule_id, file, evidence),
        FingerprintStrategy::FunctionScoped => {
            let mut hasher = Sha256::new();
            hasher.update(rule_id.as_bytes());
            hasher.update(b"\0");
            hasher.update(file.to_string_lossy().replace('\\', "/").as_bytes());
            hasher.update(b"\0");
            hasher.update(function_scope.unwrap_or_default().trim().as_bytes());
            hasher.update(b"\0");
            hasher.update(normalize_evidence(evidence).as_bytes());
            let digest = hasher.finalize();
            hex::encode(&digest[..16])
        }
        FingerprintStrategy::ContentHash => {
            let mut hasher = Sha256::new();
            hasher.update(rule_id.as_bytes());
            hasher.update(b"\0");
            hasher.update(normalize_evidence(evidence).as_bytes());
            let digest = hasher.finalize();
            hex::encode(&digest[..16])
        }
    }
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

    #[test]
    fn fingerprint_strategies_have_distinct_semantics() {
        let f_rel = fingerprint_with_strategy(
            FingerprintStrategy::FileRelative,
            "SS-001",
            Path::new("src/a.rs"),
            Some("Contract::deposit"),
            "missing auth",
        );
        assert_eq!(f_rel, fingerprint_of("SS-001", Path::new("src/a.rs"), "missing auth"));

        let fn_a = fingerprint_with_strategy(
            FingerprintStrategy::FunctionScoped,
            "SS-001",
            Path::new("src/a.rs"),
            Some("Contract::deposit"),
            "missing auth",
        );
        let fn_b = fingerprint_with_strategy(
            FingerprintStrategy::FunctionScoped,
            "SS-001",
            Path::new("src/a.rs"),
            Some("Contract::withdraw"),
            "missing auth",
        );
        assert_ne!(fn_a, fn_b);
        assert_ne!(fn_a, f_rel);

        let content_a = fingerprint_with_strategy(
            FingerprintStrategy::ContentHash,
            "SS-001",
            Path::new("src/a.rs"),
            Some("Contract::deposit"),
            "missing auth",
        );
        let content_b = fingerprint_with_strategy(
            FingerprintStrategy::ContentHash,
            "SS-001",
            Path::new("src/moved/b.rs"),
            Some("Contract::other"),
            "  missing\n auth ",
        );
        assert_eq!(content_a, content_b);
        assert_ne!(content_a, f_rel);
    }
}
