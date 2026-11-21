//! Versioned, data-only rule pack manifest and validation.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::confidence::Confidence;
use crate::severity::Severity;

/// Maximum accepted manifest size, matching the bounded pack-verification payload.
pub const MAX_PACK_MANIFEST_BYTES: usize = 10 * 1024 * 1024;

/// Current version of the rule pack manifest schema.
pub const PACK_MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Capabilities a pack may require from the scanner.
///
/// These name scanner input support only; v1 manifests contain metadata and do
/// not embed executable rules or grant packs permission to execute code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackCapability {
    /// Scanner can analyze Rust source syntax.
    RustSourceAnalysis,
    /// Scanner can inspect Cargo manifests.
    CargoManifestAnalysis,
}

impl PackCapability {
    /// Return the stable manifest spelling for this capability.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RustSourceAnalysis => "rust_source_analysis",
            Self::CargoManifestAnalysis => "cargo_manifest_analysis",
        }
    }
}

/// Errors returned while parsing or validating a rule pack manifest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PackManifestError {
    #[error("invalid pack manifest TOML: {0}")]
    Parse(String),
    #[error("invalid pack manifest: {0}")]
    Validation(String),
    #[error("pack manifest exceeds the 10485760-byte limit")]
    TooLarge,
    #[error("cannot read pack manifest at {path}: {message}")]
    Io { path: String, message: String },
}

/// Manifest defining a rule pack. Unknown fields are rejected for forward
/// compatibility: a schema update is required before adding new semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackManifest {
    pub schema_version: u32,
    pub pack: PackMetadata,
    pub rules: Vec<PackRuleMetadata>,
}

/// Metadata identifying a pack and the scanner contract it requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMetadata {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    pub min_scanner_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_scanner_version: Option<String>,
    pub capabilities: Vec<PackCapability>,
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
    /// Lowercase `sha256:` digest of this rule's canonical JSON metadata.
    pub checksum: String,
}

#[derive(Serialize)]
struct RuleChecksumPayload<'a> {
    id: &'a str,
    title: &'a str,
    category: &'a str,
    default_severity: Severity,
    default_confidence: Confidence,
    description: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<&'a str>,
}

impl PackRuleMetadata {
    /// Compute this rule's SHA-256 checksum, excluding the checksum field itself.
    pub fn expected_checksum(&self) -> String {
        let payload = RuleChecksumPayload {
            id: &self.id,
            title: &self.title,
            category: &self.category,
            default_severity: self.default_severity,
            default_confidence: self.default_confidence,
            description: &self.description,
            remediation: self.remediation.as_deref(),
        };
        let canonical = serde_json::to_vec(&payload)
            .expect("serializing a rule metadata checksum payload cannot fail");
        format!("sha256:{}", hex::encode(Sha256::digest(canonical)))
    }
}

impl PackManifest {
    /// Parses and validates a manifest from TOML text.
    pub fn parse_str(text: &str) -> Result<Self, PackManifestError> {
        if text.len() > MAX_PACK_MANIFEST_BYTES {
            return Err(PackManifestError::TooLarge);
        }
        let manifest: Self =
            toml::from_str(text).map_err(|error| PackManifestError::Parse(error.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Loads and validates a manifest file without reading beyond the size cap.
    pub fn load_file(path: &Path) -> Result<Self, PackManifestError> {
        let mut file = File::open(path).map_err(|error| PackManifestError::Io {
            path: path.display().to_string(),
            message: error.to_string(),
        })?;
        let mut content = String::new();
        file.by_ref()
            .take((MAX_PACK_MANIFEST_BYTES + 1) as u64)
            .read_to_string(&mut content)
            .map_err(|error| PackManifestError::Io {
                path: path.display().to_string(),
                message: error.to_string(),
            })?;
        Self::parse_str(&content)
    }

    /// Validate schema, compatibility declarations, and every rule checksum.
    pub fn validate(&self) -> Result<(), PackManifestError> {
        if self.schema_version != PACK_MANIFEST_SCHEMA_VERSION {
            return Err(PackManifestError::Validation(format!(
                "unsupported schema_version {}; supported version is {}",
                self.schema_version, PACK_MANIFEST_SCHEMA_VERSION
            )));
        }
        if !valid_pack_name(&self.pack.name) {
            return Err(PackManifestError::Validation(
                "pack.name must be 1-64 lowercase ASCII letters, digits, or single hyphen separators"
                    .to_string(),
            ));
        }
        parse_stable_version(&self.pack.version).ok_or_else(|| {
            PackManifestError::Validation("pack.version must be a stable X.Y.Z version".to_string())
        })?;
        let min_version =
            parse_stable_version(&self.pack.min_scanner_version).ok_or_else(|| {
                PackManifestError::Validation(
                    "pack.min_scanner_version must be a stable X.Y.Z version".to_string(),
                )
            })?;
        let max_version = self
            .pack
            .max_scanner_version
            .as_deref()
            .map(|version| {
                parse_stable_version(version).ok_or_else(|| {
                    PackManifestError::Validation(
                        "pack.max_scanner_version must be a stable X.Y.Z version".to_string(),
                    )
                })
            })
            .transpose()?;
        if max_version.is_some_and(|max| min_version > max) {
            return Err(PackManifestError::Validation(
                "min_scanner_version must not exceed max_scanner_version".to_string(),
            ));
        }
        if self.pack.capabilities.is_empty() {
            return Err(PackManifestError::Validation(
                "pack.capabilities must declare at least one required capability".to_string(),
            ));
        }
        let mut capabilities = HashSet::new();
        if self
            .pack
            .capabilities
            .iter()
            .any(|capability| !capabilities.insert(*capability))
        {
            return Err(PackManifestError::Validation(
                "pack.capabilities must not contain duplicates".to_string(),
            ));
        }
        if self.rules.is_empty() {
            return Err(PackManifestError::Validation(
                "a rule pack must contain at least one rule".to_string(),
            ));
        }
        let mut ids = HashSet::new();
        for rule in &self.rules {
            if !valid_rule_id(&rule.id) {
                return Err(PackManifestError::Validation(format!(
                    "rule id {:?} must use an uppercase prefix and numeric suffix, such as COMM-001",
                    rule.id
                )));
            }
            if !ids.insert(&rule.id) {
                return Err(PackManifestError::Validation(format!(
                    "duplicate rule id {:?}",
                    rule.id
                )));
            }
            if rule.title.trim().is_empty()
                || rule.category.trim().is_empty()
                || rule.description.trim().is_empty()
            {
                return Err(PackManifestError::Validation(format!(
                    "rule {} title, category, and description must not be empty",
                    rule.id
                )));
            }
            if rule.checksum != rule.expected_checksum() {
                return Err(PackManifestError::Validation(format!(
                    "checksum mismatch for rule {}",
                    rule.id
                )));
            }
        }
        Ok(())
    }

    /// Check scanner-version bounds and required capabilities against a scanner.
    pub fn check_compatibility(
        &self,
        scanner_version: &str,
        available_capabilities: &[PackCapability],
    ) -> Result<(), PackManifestError> {
        self.validate()?;
        let scanner_version = parse_stable_version(scanner_version).ok_or_else(|| {
            PackManifestError::Validation(
                "scanner version must be a stable X.Y.Z version".to_string(),
            )
        })?;
        let min_version = parse_stable_version(&self.pack.min_scanner_version)
            .expect("validate checks the minimum version");
        if scanner_version < min_version {
            return Err(PackManifestError::Validation(format!(
                "scanner version {} is below required minimum {}",
                format_version(scanner_version),
                self.pack.min_scanner_version
            )));
        }
        if let Some(max_version) = self.pack.max_scanner_version.as_deref() {
            let parsed_max =
                parse_stable_version(max_version).expect("validate checks max version");
            if scanner_version > parsed_max {
                return Err(PackManifestError::Validation(format!(
                    "scanner version {} exceeds supported maximum {}",
                    format_version(scanner_version),
                    max_version
                )));
            }
        }
        let available: HashSet<_> = available_capabilities.iter().copied().collect();
        if let Some(missing) = self
            .pack
            .capabilities
            .iter()
            .find(|capability| !available.contains(capability))
        {
            return Err(PackManifestError::Validation(format!(
                "scanner does not provide required capability {}",
                missing.as_str()
            )));
        }
        Ok(())
    }
}

fn valid_pack_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn valid_rule_id(id: &str) -> bool {
    let Some((prefix, suffix)) = id.split_once('-') else {
        return false;
    };
    !prefix.is_empty()
        && prefix
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        && suffix.len() >= 3
        && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn parse_stable_version(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parse_version_part(parts.next()?)?;
    let minor = parse_version_part(parts.next()?)?;
    let patch = parse_version_part(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn parse_version_part(part: &str) -> Option<u64> {
    if part.is_empty()
        || (part.len() > 1 && part.starts_with('0'))
        || !part.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    part.parse().ok()
}

fn format_version(version: (u64, u64, u64)) -> String {
    format!("{}.{}.{}", version.0, version.1, version.2)
}
