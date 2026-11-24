//! Mapping from finding severity and confidence to LSP diagnostic severity.
//!
//! The default policy is stable and documented in
//! `docs/integration/editor-integration.md`:
//!
//! | Finding severity     | LSP `DiagnosticSeverity` |
//! | -------------------- | ------------------------ |
//! | `critical`, `high`   | `Error` (1)              |
//! | `medium`             | `Warning` (2)            |
//! | `low`, `info`        | `Information` (3)        |
//!
//! Confidence does not change the default. Two opt-in adjustments exist:
//! a per-severity override table, and demotion of low-confidence findings by
//! one LSP level. Overrides are validated: unknown names and duplicate
//! severities are rejected. The policy is pure data and performs no I/O.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::confidence::Confidence;
use crate::error::ScanError;
use crate::severity::Severity;

/// LSP `DiagnosticSeverity`, ordered from most to least severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LspSeverity {
    /// LSP `Error` (1).
    Error,
    /// LSP `Warning` (2).
    Warning,
    /// LSP `Information` (3).
    Information,
    /// LSP `Hint` (4).
    Hint,
}

impl LspSeverity {
    /// Numeric value defined by the LSP specification.
    pub fn lsp_value(self) -> u8 {
        match self {
            LspSeverity::Error => 1,
            LspSeverity::Warning => 2,
            LspSeverity::Information => 3,
            LspSeverity::Hint => 4,
        }
    }

    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            LspSeverity::Error => "error",
            LspSeverity::Warning => "warning",
            LspSeverity::Information => "information",
            LspSeverity::Hint => "hint",
        }
    }

    /// One level less severe, saturating at `Hint`.
    fn demoted(self) -> Self {
        match self {
            LspSeverity::Error => LspSeverity::Warning,
            LspSeverity::Warning => LspSeverity::Information,
            LspSeverity::Information | LspSeverity::Hint => LspSeverity::Hint,
        }
    }
}

impl fmt::Display for LspSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for LspSeverity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Ok(LspSeverity::Error),
            "warning" | "warn" => Ok(LspSeverity::Warning),
            "information" | "info" => Ok(LspSeverity::Information),
            "hint" => Ok(LspSeverity::Hint),
            other => Err(format!("unknown LSP severity: {other}")),
        }
    }
}

/// Policy mapping a finding's severity and confidence to an [`LspSeverity`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SeverityPolicy {
    overrides: BTreeMap<Severity, LspSeverity>,
    demote_low_confidence: bool,
}

impl SeverityPolicy {
    /// The stable default policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Default LSP severity for a finding severity (no overrides applied).
    pub fn default_for(severity: Severity) -> LspSeverity {
        match severity {
            Severity::Critical | Severity::High => LspSeverity::Error,
            Severity::Medium => LspSeverity::Warning,
            Severity::Low | Severity::Info => LspSeverity::Information,
        }
    }

    /// Builds a policy from user-supplied `(finding severity, LSP severity)`
    /// name pairs. Every name is validated and each finding severity may be
    /// overridden at most once.
    pub fn from_overrides<'a, I>(pairs: I, demote_low_confidence: bool) -> Result<Self, ScanError>
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut overrides = BTreeMap::new();
        for (from, to) in pairs {
            let severity = from
                .parse::<Severity>()
                .map_err(|e| ScanError::Config(format!("lsp severity override: {e}")))?;
            let target = to
                .parse::<LspSeverity>()
                .map_err(|e| ScanError::Config(format!("lsp severity override: {e}")))?;
            if overrides.insert(severity, target).is_some() {
                return Err(ScanError::Config(format!(
                    "lsp severity override: duplicate entry for {severity}"
                )));
            }
        }
        Ok(Self {
            overrides,
            demote_low_confidence,
        })
    }

    /// Maps a finding to an LSP severity under this policy.
    pub fn map(&self, severity: Severity, confidence: Confidence) -> LspSeverity {
        let base = self
            .overrides
            .get(&severity)
            .copied()
            .unwrap_or_else(|| Self::default_for(severity));
        if self.demote_low_confidence && confidence == Confidence::Low {
            base.demoted()
        } else {
            base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_SEVERITIES: [Severity; 5] = [
        Severity::Info,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ];

    #[test]
    fn default_mapping_is_stable() {
        let expected = [
            (Severity::Critical, LspSeverity::Error),
            (Severity::High, LspSeverity::Error),
            (Severity::Medium, LspSeverity::Warning),
            (Severity::Low, LspSeverity::Information),
            (Severity::Info, LspSeverity::Information),
        ];
        let policy = SeverityPolicy::new();
        for (sev, lsp) in expected {
            assert_eq!(policy.map(sev, Confidence::High), lsp, "{sev}");
        }
    }

    #[test]
    fn default_ignores_confidence() {
        let policy = SeverityPolicy::new();
        for sev in ALL_SEVERITIES {
            let low = policy.map(sev, Confidence::Low);
            assert_eq!(low, policy.map(sev, Confidence::Medium));
            assert_eq!(low, policy.map(sev, Confidence::High));
        }
    }

    #[test]
    fn lsp_numeric_values_match_spec() {
        assert_eq!(LspSeverity::Error.lsp_value(), 1);
        assert_eq!(LspSeverity::Warning.lsp_value(), 2);
        assert_eq!(LspSeverity::Information.lsp_value(), 3);
        assert_eq!(LspSeverity::Hint.lsp_value(), 4);
    }

    #[test]
    fn override_replaces_only_named_severity() {
        let policy =
            SeverityPolicy::from_overrides([("medium", "error"), ("info", "hint")], false).unwrap();
        assert_eq!(
            policy.map(Severity::Medium, Confidence::High),
            LspSeverity::Error
        );
        assert_eq!(
            policy.map(Severity::Info, Confidence::High),
            LspSeverity::Hint
        );
        assert_eq!(
            policy.map(Severity::High, Confidence::High),
            LspSeverity::Error
        );
        assert_eq!(
            policy.map(Severity::Low, Confidence::High),
            LspSeverity::Information
        );
    }

    #[test]
    fn override_accepts_aliases_and_case() {
        let policy = SeverityPolicy::from_overrides([(" CRIT ", "Warn")], false).unwrap();
        assert_eq!(
            policy.map(Severity::Critical, Confidence::High),
            LspSeverity::Warning
        );
    }

    #[test]
    fn rejects_unknown_names_and_duplicates() {
        assert!(SeverityPolicy::from_overrides([("severe", "error")], false).is_err());
        assert!(SeverityPolicy::from_overrides([("high", "fatal")], false).is_err());
        assert!(SeverityPolicy::from_overrides([("", "")], false).is_err());
        assert!(
            SeverityPolicy::from_overrides([("high", "error"), ("HIGH", "hint")], false).is_err()
        );
    }

    #[test]
    fn low_confidence_demotion_is_opt_in_and_saturates() {
        let policy = SeverityPolicy::from_overrides([], true).unwrap();
        assert_eq!(
            policy.map(Severity::High, Confidence::Low),
            LspSeverity::Warning
        );
        assert_eq!(
            policy.map(Severity::Medium, Confidence::Low),
            LspSeverity::Information
        );
        assert_eq!(
            policy.map(Severity::Info, Confidence::Low),
            LspSeverity::Hint
        );
        assert_eq!(
            policy.map(Severity::High, Confidence::Medium),
            LspSeverity::Error
        );
        let hint = SeverityPolicy::from_overrides([("info", "hint")], true).unwrap();
        assert_eq!(hint.map(Severity::Info, Confidence::Low), LspSeverity::Hint);
    }
}
