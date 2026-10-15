//! Finding severity.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Severity of a security finding, ordered from least to most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; no direct security impact.
    Info,
    /// Minor weakness or hardening opportunity.
    Low,
    /// Security weakness that contributes to an exploit.
    Medium,
    /// Serious security impact under plausible conditions.
    High,
    /// Direct loss of funds or total loss of access control.
    Critical,
}

impl Severity {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    /// Numeric rank (higher is more severe).
    pub fn rank(self) -> u8 {
        match self {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    /// Returns true if `self` is at least as severe as `threshold`.
    pub fn meets(self, threshold: Severity) -> bool {
        self.rank() >= threshold.rank()
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            other => Err(format!("unknown severity: {other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_ascending() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn meets_threshold() {
        assert!(Severity::High.meets(Severity::Medium));
        assert!(Severity::Medium.meets(Severity::Medium));
        assert!(!Severity::Low.meets(Severity::Medium));
    }

    #[test]
    fn parses_every_accepted_alias() {
        // Full alias table for Severity::from_str.
        let cases: &[(&str, Severity)] = &[
            ("info", Severity::Info),
            ("low", Severity::Low),
            ("medium", Severity::Medium),
            ("med", Severity::Medium),
            ("high", Severity::High),
            ("critical", Severity::Critical),
            ("crit", Severity::Critical),
        ];
        for (alias, expected) in cases {
            let parsed = alias
                .parse::<Severity>()
                .unwrap_or_else(|e| panic!("{alias:?} -> {e}"));
            assert_eq!(parsed, *expected, "alias {alias:?}");
        }
    }

    #[test]
    fn parsing_is_case_insensitive_and_trims_whitespace() {
        assert_eq!("MEDIUM".parse::<Severity>().unwrap(), Severity::Medium);
        assert_eq!("  CRIT  ".parse::<Severity>().unwrap(), Severity::Critical);
        assert_eq!("Med".parse::<Severity>().unwrap(), Severity::Medium);
    }

    #[test]
    fn rejects_unknown_severity_values() {
        // Each value remains unknown after `from_str` trims and lowercases it.
        for bad in [
            "",
            "severe",
            "critical2",
            "moderate",
            "urgent",
            "warn",
            "medium-level",
            "infore",
        ] {
            assert!(bad.parse::<Severity>().is_err(), "{bad:?} must be rejected");
        }
    }
}
