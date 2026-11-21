//! Rule pack conformance runner.
//!
//! Conformance tests verify that a fixture pack loads safely, passes
//! cryptographic and compatibility checks, and produces its expected known
//! findings when executed against the current scanner.

use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::config::ScanConfig;
use crate::engine;
use crate::model::DiagnosticCode;
use crate::pack::loader::{LoadedPack, PackLoadError, PackLoader};
use crate::pack::signing::{KeyRing, VerificationPolicy};
use crate::registry::RuleRegistry;
use crate::severity::Severity;

/// Maximum allowed size of `conformance.toml` in bytes (256 KiB).
pub const MAX_CONFORMANCE_SPEC_SIZE: usize = 256 * 1024;

/// Maximum number of expected findings in a single conformance spec.
pub const MAX_EXPECTED_FINDINGS: usize = 256;

/// Conformance specification stored in `conformance.toml` inside a fixture pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConformanceSpec {
    /// Relative path inside the pack directory to the target contract/project.
    pub target: String,
    /// Known findings that must be reported by the current scanner.
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
    /// Rule IDs that must not be reported for the target.
    #[serde(default)]
    pub forbidden_rules: Vec<String>,
}

/// A single expected finding assertion in [`ConformanceSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedFinding {
    /// Expected rule identifier (e.g. `"SS-001"`).
    pub rule_id: String,
    /// Optional required severity.
    #[serde(default)]
    pub severity: Option<Severity>,
    /// Optional required confidence.
    #[serde(default)]
    pub confidence: Option<Confidence>,
    /// Minimum number of matching findings required (defaults to 1).
    #[serde(default = "default_min_count")]
    pub min_count: usize,
}

fn default_min_count() -> usize {
    1
}

/// Summary produced when a pack passes conformance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConformanceReport {
    /// Verified and validated pack.
    pub pack: LoadedPack,
    /// Total findings reported by the scanner on the conformance target.
    pub total_findings: usize,
    /// Number of expected-finding assertions satisfied.
    pub matched_expectations: usize,
}

/// Errors raised when running pack conformance checks.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConformanceError {
    /// Pack could not be loaded safely.
    #[error("pack load failed: {0}")]
    PackLoad(#[from] PackLoadError),

    /// Conformance specification could not be read or parsed.
    #[error("invalid conformance spec: {0}")]
    InvalidSpec(String),

    /// Target path in conformance spec is unsafe or missing.
    #[error("unsafe conformance target: {0}")]
    UnsafeTarget(String),

    /// Scanner execution failed on the conformance target.
    #[error("scanner failed on conformance target: {0}")]
    ScanFailed(String),

    /// A rule panicked while scanning the conformance target.
    #[error("rule panicked while scanning conformance target: {0}")]
    RulePanicked(String),

    /// Expected known finding was missing or did not meet criteria.
    #[error(
        "expected at least {expected_min} finding(s) for rule '{rule_id}'{qualifier}, found {actual}"
    )]
    MissingExpectedFinding {
        rule_id: String,
        qualifier: String,
        expected_min: usize,
        actual: usize,
    },

    /// A forbidden rule triggered on the conformance target.
    #[error("forbidden rule '{rule_id}' triggered {count} time(s)")]
    ForbiddenRuleTriggered { rule_id: String, count: usize },
}

/// Runs conformance checks for fixture packs against the current scanner.
pub struct ConformanceRunner;

impl ConformanceRunner {
    /// Verifies, loads, and runs a conformance fixture pack against the
    /// default built-in [`RuleRegistry`].
    pub fn run(
        pack_dir: &Path,
        keyring: &KeyRing,
        policy: VerificationPolicy,
    ) -> Result<ConformanceReport, ConformanceError> {
        let pack = PackLoader::load_dir(pack_dir, keyring, policy)?;
        let spec = load_conformance_spec(pack_dir)?;
        let target_path = resolve_safe_target(pack_dir, &spec.target)?;

        let registry = RuleRegistry::with_default_rules();
        let outcome = engine::run_scan(&target_path, &ScanConfig::default(), &registry)
            .map_err(|e| ConformanceError::ScanFailed(e.to_string()))?;

        if let Some(diag) = outcome
            .diagnostics
            .iter()
            .find(|d| d.code == DiagnosticCode::RulePanicked)
        {
            return Err(ConformanceError::RulePanicked(diag.message.clone()));
        }

        for expected in &spec.expected_findings {
            let actual = outcome
                .findings
                .iter()
                .filter(|f| {
                    f.rule_id == expected.rule_id
                        && expected.severity.is_none_or(|s| f.severity == s)
                        && expected.confidence.is_none_or(|c| f.confidence == c)
                })
                .count();

            if actual < expected.min_count {
                let mut parts = Vec::new();
                if let Some(sev) = expected.severity {
                    parts.push(format!("severity={sev}"));
                }
                if let Some(conf) = expected.confidence {
                    parts.push(format!("confidence={conf}"));
                }
                let qualifier = if parts.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", parts.join(", "))
                };
                return Err(ConformanceError::MissingExpectedFinding {
                    rule_id: expected.rule_id.clone(),
                    qualifier,
                    expected_min: expected.min_count,
                    actual,
                });
            }
        }

        for forbidden in &spec.forbidden_rules {
            let count = outcome
                .findings
                .iter()
                .filter(|f| &f.rule_id == forbidden)
                .count();
            if count > 0 {
                return Err(ConformanceError::ForbiddenRuleTriggered {
                    rule_id: forbidden.clone(),
                    count,
                });
            }
        }

        Ok(ConformanceReport {
            pack,
            total_findings: outcome.findings.len(),
            matched_expectations: spec.expected_findings.len(),
        })
    }
}

fn load_conformance_spec(pack_dir: &Path) -> Result<ConformanceSpec, ConformanceError> {
    let spec_path = pack_dir.join("conformance.toml");
    let meta = std::fs::symlink_metadata(&spec_path).map_err(|e| {
        ConformanceError::InvalidSpec(format!("cannot access {}: {e}", spec_path.display()))
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(ConformanceError::InvalidSpec(format!(
            "{} must be a regular file",
            spec_path.display()
        )));
    }
    if meta.len() > MAX_CONFORMANCE_SPEC_SIZE as u64 {
        return Err(ConformanceError::InvalidSpec(format!(
            "conformance.toml exceeds {MAX_CONFORMANCE_SPEC_SIZE} bytes"
        )));
    }
    let text = std::fs::read_to_string(&spec_path).map_err(|e| {
        ConformanceError::InvalidSpec(format!("cannot read {}: {e}", spec_path.display()))
    })?;
    let spec: ConformanceSpec = toml::from_str(&text)
        .map_err(|e| ConformanceError::InvalidSpec(format!("invalid TOML: {e}")))?;

    if spec.expected_findings.is_empty() {
        return Err(ConformanceError::InvalidSpec(
            "conformance.toml must declare at least one expected finding".to_string(),
        ));
    }
    if spec.expected_findings.len() > MAX_EXPECTED_FINDINGS {
        return Err(ConformanceError::InvalidSpec(format!(
            "conformance.toml declares {} expected findings, exceeding limit of {MAX_EXPECTED_FINDINGS}",
            spec.expected_findings.len()
        )));
    }
    Ok(spec)
}

fn resolve_safe_target(
    pack_dir: &Path,
    relative: &str,
) -> Result<std::path::PathBuf, ConformanceError> {
    let trimmed = relative.trim();
    if trimmed.is_empty() {
        return Err(ConformanceError::UnsafeTarget(
            "conformance target must not be empty".to_string(),
        ));
    }
    let rel_path = Path::new(trimmed);
    if rel_path.is_absolute() {
        return Err(ConformanceError::UnsafeTarget(format!(
            "conformance target '{trimmed}' must be relative"
        )));
    }
    for component in rel_path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(ConformanceError::UnsafeTarget(format!(
                "conformance target '{trimmed}' escapes pack directory"
            )));
        }
    }

    let joined = pack_dir.join(rel_path);
    let meta = std::fs::symlink_metadata(&joined).map_err(|e| {
        ConformanceError::UnsafeTarget(format!("cannot access target {}: {e}", joined.display()))
    })?;
    if meta.file_type().is_symlink() {
        return Err(ConformanceError::UnsafeTarget(format!(
            "conformance target {} must not be a symlink",
            joined.display()
        )));
    }
    Ok(joined)
}
