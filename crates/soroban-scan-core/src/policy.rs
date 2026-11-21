//! Versioned policy documents (#370, #371).
//!
//! A policy file collects fail thresholds, report thresholds, and suppressions
//! into one reviewable document. Unknown keys are errors. Precedence is:
//! built-in defaults < discovered configuration < policy file < explicit CLI
//! flags.

use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::config::{ScanConfig, SuppressionRule, WaiverRule};
use crate::error::ScanError;
use crate::severity::Severity;

/// Supported policy schema version.
pub const POLICY_SCHEMA_VERSION: u32 = 1;

fn default_schema_version() -> u32 {
    POLICY_SCHEMA_VERSION
}

/// A versioned policy document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Schema version; currently `1`.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// Fail threshold: `none`, or `info`/`low`/`medium`/`high`/`critical`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fail_on: Option<String>,
    /// Minimum severity to report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    /// Minimum confidence to report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_confidence: Option<Confidence>,
    /// Path- and rule-scoped suppressions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressions: Vec<SuppressionRule>,
    /// Time-limited, owned suppressions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub waivers: Vec<WaiverRule>,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        PolicyDocument {
            schema_version: POLICY_SCHEMA_VERSION,
            fail_on: None,
            min_severity: None,
            min_confidence: None,
            suppressions: Vec::new(),
            waivers: Vec::new(),
        }
    }
}

impl PolicyDocument {
    /// Validate the version, fail threshold, suppressions, and waivers.
    pub fn validate(&self) -> Result<(), ScanError> {
        if self.schema_version != POLICY_SCHEMA_VERSION {
            return Err(ScanError::Config(format!(
                "unsupported policy schema_version {}; expected {POLICY_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        self.fail_threshold()?;
        for (index, suppression) in self.suppressions.iter().enumerate() {
            suppression.validate().map_err(|error| {
                ScanError::Config(format!("invalid policy suppressions[{index}]: {error}"))
            })?;
        }
        for (index, waiver) in self.waivers.iter().enumerate() {
            waiver.validate().map_err(|error| {
                ScanError::Config(format!("invalid policy waivers[{index}]: {error}"))
            })?;
        }
        Ok(())
    }

    /// Resolve `fail_on` to a severity threshold (`None` means never fail).
    pub fn fail_threshold(&self) -> Result<Option<Severity>, ScanError> {
        let Some(value) = self.fail_on.as_deref() else {
            return Ok(None);
        };
        let value = value.trim();
        if value.eq_ignore_ascii_case("none") {
            return Ok(None);
        }
        Severity::from_str(value)
            .map(Some)
            .map_err(|_| ScanError::Config(format!("invalid policy fail_on: `{value}`")))
    }

    /// Load and validate a policy from TOML, YAML, or JSON.
    pub fn load(path: &Path) -> Result<Self, ScanError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            ScanError::Config(format!("cannot read policy {}: {error}", path.display()))
        })?;
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let invalid = |error: String| {
            ScanError::Config(format!("invalid policy {}: {error}", path.display()))
        };
        let policy = match extension.as_str() {
            "toml" => {
                toml::from_str::<PolicyDocument>(&text).map_err(|error| invalid(error.to_string()))
            }
            "json" => serde_json::from_str::<PolicyDocument>(&text)
                .map_err(|error| invalid(error.to_string())),
            _ => {
                return Err(ScanError::Config(format!(
                    "policy {} must use a .toml or .json extension",
                    path.display()
                )))
            }
        }?;
        policy.validate()?;
        Ok(policy)
    }

    /// Apply policy values to `config`.
    ///
    /// CLI flags are applied afterwards, so an explicit flag still wins.
    pub fn apply(&self, config: &mut ScanConfig) {
        if let Some(severity) = self.min_severity {
            config.min_severity = severity;
        }
        if let Some(confidence) = self.min_confidence {
            config.min_confidence = confidence;
        }
        config
            .suppressions
            .extend(self.suppressions.iter().cloned());
        config.waivers.extend(self.waivers.iter().cloned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_toml_policy() {
        let policy: PolicyDocument = toml::from_str(
            r#"
schema_version = 1
fail_on = "medium"
min_severity = "low"
min_confidence = "medium"

[[suppressions]]
path = "tests/**"
rule = "SS-001"
reason = "test-only fixture"
"#,
        )
        .unwrap();
        assert!(policy.validate().is_ok());
        assert_eq!(policy.fail_threshold().unwrap(), Some(Severity::Medium));
        let mut config = ScanConfig::default();
        policy.apply(&mut config);
        assert_eq!(config.min_severity, Severity::Low);
        assert_eq!(config.min_confidence, Confidence::Medium);
        assert_eq!(config.suppressions.len(), 1);
    }

    #[test]
    fn unknown_keys_are_errors() {
        assert!(toml::from_str::<PolicyDocument>("mystery = true").is_err());
    }

    #[test]
    fn rejects_bad_versions_and_thresholds() {
        let mut policy = PolicyDocument::default();
        policy.schema_version = 99;
        assert!(policy.validate().is_err());

        let policy = PolicyDocument {
            fail_on: Some("sometimes".to_string()),
            ..PolicyDocument::default()
        };
        assert!(policy.validate().is_err());

        let none = PolicyDocument {
            fail_on: Some("none".to_string()),
            ..PolicyDocument::default()
        };
        assert_eq!(none.fail_threshold().unwrap(), None);
    }

    #[test]
    fn loads_json_policy() {
        let directory = tempfile::tempdir().unwrap();
        let json = directory.path().join("policy.json");
        std::fs::write(&json, r#"{"schema_version":1,"fail_on":"high"}"#).unwrap();
        assert_eq!(
            PolicyDocument::load(&json)
                .unwrap()
                .fail_threshold()
                .unwrap(),
            Some(Severity::High)
        );
    }
}
