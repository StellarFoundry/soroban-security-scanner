//! Rule pack manifest data model and parsing.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::severity::Severity;

/// Manifest defining a rule pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    pub pack: PackMetadata,
    #[serde(default)]
    pub rules: Vec<PackRuleMetadata>,
}

/// Metadata identifying a rule pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_scanner_version: Option<String>,
}

/// Metadata describing a rule provided by a pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRuleMetadata {
    pub id: String,
    pub title: String,
    pub category: String,
    pub default_severity: Severity,
    pub default_confidence: Confidence,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
}

impl PackManifest {
    /// Parses a pack manifest from TOML text.
    pub fn parse_str(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Loads a pack manifest from a file path.
    pub fn load_file(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read pack manifest at {}: {e}", path.display()))?;
        Self::parse_str(&content)
            .map_err(|e| format!("invalid pack manifest at {}: {e}", path.display()))
    }
}
