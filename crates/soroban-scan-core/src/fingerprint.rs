//! Configurable finding-fingerprint strategies.
//!
//! The default strategy hashes the rule id, the file path, and the normalized
//! evidence, and deliberately ignores line and column so that unrelated line
//! shifts do not invalidate a baseline. This is byte-for-byte the historical
//! behavior, so existing baselines remain valid.
//!
//! Opt-in strategies trade stability for precision:
//!
//! - [`FingerprintStrategy::RuleFileLineEvidence`] includes the line number.
//! - [`FingerprintStrategy::RuleFileLineColumnEvidence`] includes the line and
//!   column.
//! - [`FingerprintStrategy::PathIndependent`] omits the file path so findings
//!   survive file renames and moves. Omitting the path increases the chance of
//!   collisions between identical findings in different files.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::finding::{fingerprint_of, normalize_evidence};

/// Selects which finding fields contribute to the fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FingerprintStrategy {
    /// Rule id, file path, and evidence. The default and backward-compatible mode.
    #[default]
    RuleFileEvidence,
    /// Rule id, file path, line number, and evidence.
    RuleFileLineEvidence,
    /// Rule id, file path, line number, column, and evidence.
    RuleFileLineColumnEvidence,
    /// Rule id and evidence only; ignores the file path and position.
    PathIndependent,
}

impl FingerprintStrategy {
    /// Every strategy, in documentation order.
    pub const ALL: &'static [FingerprintStrategy] = &[
        FingerprintStrategy::RuleFileEvidence,
        FingerprintStrategy::RuleFileLineEvidence,
        FingerprintStrategy::RuleFileLineColumnEvidence,
        FingerprintStrategy::PathIndependent,
    ];

    /// The stable wire name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FingerprintStrategy::RuleFileEvidence => "rule-file-evidence",
            FingerprintStrategy::RuleFileLineEvidence => "rule-file-line-evidence",
            FingerprintStrategy::RuleFileLineColumnEvidence => "rule-file-line-column-evidence",
            FingerprintStrategy::PathIndependent => "path-independent",
        }
    }

    /// A short description of the trade-off.
    #[must_use]
    pub fn description(self) -> &'static str {
        match self {
            FingerprintStrategy::RuleFileEvidence => {
                "rule id, file path, and evidence (default; stable across line shifts)"
            }
            FingerprintStrategy::RuleFileLineEvidence => {
                "rule id, file path, line, and evidence (line-sensitive)"
            }
            FingerprintStrategy::RuleFileLineColumnEvidence => {
                "rule id, file path, line, column, and evidence (position-sensitive)"
            }
            FingerprintStrategy::PathIndependent => {
                "rule id and evidence only (survives renames; higher collision risk)"
            }
        }
    }

    /// Whether the strategy includes the file path.
    #[must_use]
    pub fn includes_path(self) -> bool {
        !matches!(self, FingerprintStrategy::PathIndependent)
    }

    /// Parses a strategy name. Accepts the stable kebab-case name and `default`.
    pub fn parse(value: &str) -> Result<Self, String> {
        let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
        let strategy = match normalized.as_str() {
            "rule-file-evidence" | "default" => FingerprintStrategy::RuleFileEvidence,
            "rule-file-line-evidence" => FingerprintStrategy::RuleFileLineEvidence,
            "rule-file-line-column-evidence" => FingerprintStrategy::RuleFileLineColumnEvidence,
            "path-independent" => FingerprintStrategy::PathIndependent,
            other => {
                return Err(format!(
                    "unknown fingerprint strategy `{other}`; expected rule-file-evidence, \
                     rule-file-line-evidence, rule-file-line-column-evidence, or \
                     path-independent"
                ))
            }
        };
        Ok(strategy)
    }

    /// Computes a fingerprint using this strategy.
    #[must_use]
    pub fn compute(
        self,
        rule_id: &str,
        file: &Path,
        line: usize,
        column: Option<usize>,
        evidence: &str,
    ) -> String {
        match self {
            // Reuse the historical implementation so the default is unchanged.
            FingerprintStrategy::RuleFileEvidence => fingerprint_of(rule_id, file, evidence),
            FingerprintStrategy::RuleFileLineEvidence => {
                hash_parts(rule_id, Some(file), Some(line), None, evidence)
            }
            FingerprintStrategy::RuleFileLineColumnEvidence => {
                hash_parts(rule_id, Some(file), Some(line), column, evidence)
            }
            FingerprintStrategy::PathIndependent => hash_parts(rule_id, None, None, None, evidence),
        }
    }
}

impl fmt::Display for FingerprintStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for FingerprintStrategy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        FingerprintStrategy::parse(value)
    }
}

fn hash_parts(
    rule_id: &str,
    file: Option<&Path>,
    line: Option<usize>,
    column: Option<usize>,
    evidence: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(b"\0");
    if let Some(file) = file {
        hasher.update(file.to_string_lossy().replace('\\', "/").as_bytes());
        hasher.update(b"\0");
    }
    if let Some(line) = line {
        hasher.update(line.to_string().as_bytes());
        hasher.update(b"\0");
    }
    if let Some(column) = column {
        hasher.update(column.to_string().as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(normalize_evidence(evidence).as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute(strategy: FingerprintStrategy, file: &str, line: usize, col: usize) -> String {
        strategy.compute(
            "SS-001",
            Path::new(file),
            line,
            Some(col),
            "missing require_auth",
        )
    }

    #[test]
    fn default_strategy_matches_the_historical_fingerprint() {
        let legacy = fingerprint_of("SS-001", Path::new("src/lib.rs"), "missing require_auth");
        assert_eq!(
            FingerprintStrategy::RuleFileEvidence.compute(
                "SS-001",
                Path::new("src/lib.rs"),
                42,
                Some(7),
                "missing require_auth"
            ),
            legacy
        );
        assert_eq!(
            FingerprintStrategy::default().as_str(),
            "rule-file-evidence"
        );
    }

    #[test]
    fn line_and_column_strategies_are_position_sensitive() {
        let default = compute(FingerprintStrategy::RuleFileEvidence, "src/lib.rs", 10, 1);
        let line = compute(
            FingerprintStrategy::RuleFileLineEvidence,
            "src/lib.rs",
            10,
            1,
        );
        assert_ne!(default, line);

        let line_shifted = compute(
            FingerprintStrategy::RuleFileLineEvidence,
            "src/lib.rs",
            11,
            1,
        );
        assert_ne!(line, line_shifted);
        assert_eq!(
            compute(FingerprintStrategy::RuleFileEvidence, "src/lib.rs", 11, 1),
            default,
            "the default must ignore line shifts"
        );

        let column = compute(
            FingerprintStrategy::RuleFileLineColumnEvidence,
            "src/lib.rs",
            10,
            1,
        );
        let column_shifted = compute(
            FingerprintStrategy::RuleFileLineColumnEvidence,
            "src/lib.rs",
            10,
            2,
        );
        assert_ne!(column, column_shifted);
    }

    #[test]
    fn path_independent_strategy_ignores_the_file() {
        let a = compute(FingerprintStrategy::PathIndependent, "src/a.rs", 10, 1);
        let b = compute(
            FingerprintStrategy::PathIndependent,
            "src/renamed.rs",
            10,
            1,
        );
        assert_eq!(a, b);
        assert!(!FingerprintStrategy::PathIndependent.includes_path());

        let default_a = compute(FingerprintStrategy::RuleFileEvidence, "src/a.rs", 10, 1);
        let default_b = compute(
            FingerprintStrategy::RuleFileEvidence,
            "src/renamed.rs",
            10,
            1,
        );
        assert_ne!(default_a, default_b);
    }

    #[test]
    fn paths_are_compared_with_forward_slashes() {
        let unix = compute(
            FingerprintStrategy::RuleFileEvidence,
            "src/nested/lib.rs",
            1,
            1,
        );
        let windows = compute(
            FingerprintStrategy::RuleFileEvidence,
            r"src\nested\lib.rs",
            1,
            1,
        );
        assert_eq!(unix, windows);
    }

    #[test]
    fn names_round_trip() {
        for strategy in FingerprintStrategy::ALL {
            assert_eq!(
                FingerprintStrategy::parse(strategy.as_str()).unwrap(),
                *strategy
            );
            assert_eq!(strategy.to_string(), strategy.as_str());
        }
        assert_eq!(
            FingerprintStrategy::parse("default").unwrap(),
            FingerprintStrategy::RuleFileEvidence
        );
        assert!(FingerprintStrategy::parse("nope").is_err());
    }

    #[test]
    fn strategies_serialize_as_kebab_case() {
        let json = serde_json::to_string(&FingerprintStrategy::PathIndependent).unwrap();
        assert_eq!(json, "\"path-independent\"");
        let parsed: FingerprintStrategy =
            serde_json::from_str("\"rule-file-line-evidence\"").expect("deserialize strategy");
        assert_eq!(parsed, FingerprintStrategy::RuleFileLineEvidence);
    }
}
