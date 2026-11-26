//! Local-only false-positive feedback records.
//!
//! Feedback is deliberately minimal: a rule id, the stable finding fingerprint
//! (exposed by the CLI as `--span-hash`), and a short redacted reason. Records
//! never contain source text, evidence, absolute paths, timestamps, or network
//! identifiers. Nothing in this module performs network access.

use serde::{Deserialize, Serialize};

use crate::ai::redact;
use crate::error::ScanError;
use crate::registry::is_valid_rule_id;

/// Version of the local feedback document.
pub const FEEDBACK_SCHEMA_VERSION: u32 = 1;
/// Stable tool marker stored in feedback documents.
pub const FEEDBACK_TOOL: &str = "soroban-scan";
/// Fixed file name used by the CLI.
pub const FEEDBACK_FILE_NAME: &str = "feedback.json";
/// Maximum size of a feedback document on disk.
pub const MAX_FEEDBACK_BYTES: usize = 1024 * 1024;
/// Maximum number of feedback entries in one document.
pub const MAX_FEEDBACK_ENTRIES: usize = 1024;
/// Maximum size of a user-supplied reason.
pub const MAX_REASON_BYTES: usize = 512;
/// Expected length of a finding fingerprint in hexadecimal characters.
pub const FINGERPRINT_HEX_LEN: usize = 32;

/// One locally recorded false-positive report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackEntry {
    /// Rule that produced the finding.
    pub rule_id: String,
    /// Stable finding fingerprint, stored as lowercase hex.
    pub fingerprint: String,
    /// Short redacted explanation, when supplied.
    pub reason: Option<String>,
}

/// Bounded, deterministic collection of local feedback records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedbackStore {
    /// Schema version of this document.
    pub schema_version: u32,
    /// Tool that wrote the document.
    pub tool: String,
    /// Feedback entries, sorted and deduplicated.
    pub entries: Vec<FeedbackEntry>,
}

impl Default for FeedbackStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FeedbackStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            schema_version: FEEDBACK_SCHEMA_VERSION,
            tool: FEEDBACK_TOOL.to_string(),
            entries: Vec::new(),
        }
    }

    /// Parse and validate a feedback document.
    pub fn from_json(text: &str) -> std::result::Result<Self, ScanError> {
        let store: Self = serde_json::from_str(text).map_err(|error| ScanError::Parse {
            path: "feedback.json".into(),
            message: error.to_string(),
        })?;
        store.validate()?;
        Ok(store.canonicalized())
    }

    /// Serialize the store as stable, bounded JSON.
    pub fn to_json(&self) -> std::result::Result<String, ScanError> {
        let text = serde_json::to_string_pretty(self).map_err(|error| ScanError::Parse {
            path: "feedback.json".into(),
            message: error.to_string(),
        })?;
        if text.len() > MAX_FEEDBACK_BYTES {
            return Err(ScanError::Parse {
                path: "feedback.json".into(),
                message: "feedback document exceeds the size limit".to_string(),
            });
        }
        Ok(text)
    }

    /// Validate the store version, tool marker, entry bounds, and each entry.
    pub fn validate(&self) -> std::result::Result<(), ScanError> {
        if self.schema_version != FEEDBACK_SCHEMA_VERSION {
            return Err(ScanError::Parse {
                path: "feedback.json".into(),
                message: format!(
                    "unsupported feedback schema_version `{}`; expected `{}`",
                    self.schema_version, FEEDBACK_SCHEMA_VERSION
                ),
            });
        }
        if self.tool != FEEDBACK_TOOL {
            return Err(ScanError::Parse {
                path: "feedback.json".into(),
                message: format!("unexpected feedback tool `{}`", self.tool),
            });
        }
        if self.entries.len() > MAX_FEEDBACK_ENTRIES {
            return Err(ScanError::Parse {
                path: "feedback.json".into(),
                message: format!("feedback contains more than {MAX_FEEDBACK_ENTRIES} entries"),
            });
        }
        for entry in &self.entries {
            validate_entry(entry)?;
        }
        Ok(())
    }

    /// Add an entry, deduplicating identical records and sorting deterministically.
    ///
    /// Returns `true` when a new entry was added.
    pub fn add(&mut self, entry: FeedbackEntry) -> bool {
        if self.entries.contains(&entry) {
            return false;
        }
        self.entries.push(entry);
        self.entries.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
                .then_with(|| a.reason.cmp(&b.reason))
        });
        true
    }

    fn canonicalized(mut self) -> Self {
        let mut seen = Vec::new();
        self.entries.retain(|entry| {
            if seen.contains(entry) {
                false
            } else {
                seen.push(entry.clone());
                true
            }
        });
        self.entries.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then_with(|| a.fingerprint.cmp(&b.fingerprint))
                .then_with(|| a.reason.cmp(&b.reason))
        });
        self
    }
}

/// Normalize and validate a finding fingerprint.
pub fn normalize_fingerprint(value: &str) -> std::result::Result<String, String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != FINGERPRINT_HEX_LEN
        || !normalized.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err(format!(
            "span hash must be {FINGERPRINT_HEX_LEN} hexadecimal characters"
        ));
    }
    Ok(normalized)
}

/// Validate, trim, and redact a user-supplied reason.
pub fn normalize_reason(value: &str) -> std::result::Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("reason must not be empty".to_string());
    }
    if trimmed.len() > MAX_REASON_BYTES {
        return Err(format!("reason must be at most {MAX_REASON_BYTES} bytes"));
    }
    Ok(redact(trimmed))
}

fn validate_entry(entry: &FeedbackEntry) -> std::result::Result<(), ScanError> {
    if !is_valid_rule_id(&entry.rule_id) {
        return Err(ScanError::Parse {
            path: "feedback.json".into(),
            message: format!("invalid rule id `{}`", entry.rule_id),
        });
    }
    if normalize_fingerprint(&entry.fingerprint).is_err() {
        return Err(ScanError::Parse {
            path: "feedback.json".into(),
            message: format!("invalid fingerprint `{}`", entry.fingerprint),
        });
    }
    if let Some(reason) = &entry.reason {
        if normalize_reason(reason).is_err() {
            return Err(ScanError::Parse {
                path: "feedback.json".into(),
                message: "invalid feedback reason".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(rule: &str, fingerprint: &str, reason: Option<&str>) -> FeedbackEntry {
        FeedbackEntry {
            rule_id: rule.to_string(),
            fingerprint: fingerprint.to_string(),
            reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn fingerprint_validation_normalizes_uppercase() {
        assert_eq!(
            normalize_fingerprint("A1B2C3D4E5F60718293A4B5C6D7E8F90").expect("valid hash"),
            "a1b2c3d4e5f60718293a4b5c6d7e8f90"
        );
        assert!(normalize_fingerprint("abc").is_err());
        assert!(normalize_fingerprint("g1b2c3d4e5f60718293a4b5c6d7e8f90").is_err());
    }

    #[test]
    fn reason_is_bounded_and_redacted() {
        let redacted = normalize_reason("token = sk-live-example-secret").expect("reason");
        assert!(!redacted.contains("sk-live-example-secret"));
        assert!(normalize_reason("   ").is_err());
        assert!(normalize_reason(&"x".repeat(MAX_REASON_BYTES + 1)).is_err());
    }

    #[test]
    fn store_json_round_trip_is_canonical() {
        let mut store = FeedbackStore::new();
        store.add(entry("SS-002", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", None));
        store.add(entry(
            "SS-001",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            Some("reviewed"),
        ));
        let parsed = FeedbackStore::from_json(&store.to_json().expect("serialize")).expect("parse");
        assert_eq!(parsed, store);
        assert_eq!(parsed.entries[0].rule_id, "SS-001");
    }

    #[test]
    fn store_rejects_bad_versions_and_entries() {
        let text = r#"{"schema_version":999,"tool":"soroban-scan","entries":[]}"#;
        assert!(FeedbackStore::from_json(text).is_err());

        let mut store = FeedbackStore::new();
        store.entries.push(entry(
            "NOT-A-RULE",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            None,
        ));
        assert!(store.validate().is_err());
    }

    #[test]
    fn duplicate_entries_are_deduplicated() {
        let mut store = FeedbackStore::new();
        assert!(store.add(entry("SS-001", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None)));
        assert!(!store.add(entry("SS-001", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", None)));
        assert_eq!(store.entries.len(), 1);
    }
}
