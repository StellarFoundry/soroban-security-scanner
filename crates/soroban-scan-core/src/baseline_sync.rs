//! GitHub code-scanning baseline synchronization.
//!
//! Provides an artifact storage abstraction, envelope verification, and
//! overwrite protection for sharing security baselines across CI environments.
//!
//! # Architecture
//!
//! * [`BaselineStore`] — trait abstracting remote artifact storage (mock, directory, etc.)
//! * [`BaselineEnvelope`] — versioned envelope containing registry fingerprint, revision,
//!   content hash, and serialized baseline payload.
//! * Key validation — strict charset `[A-Za-z0-9._-]` and length bounds before any I/O.
//! * Fail-closed verification — size limit, envelope syntax, schema version, registry
//!   fingerprint, and SHA-256 payload content hash.
//! * Monotonic revision tracking and overwrite protection.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::baseline::Baseline;
use crate::registry::RuleRegistry;

/// Current envelope schema version.
pub const CURRENT_ENVELOPE_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted envelope size in bytes (64 MiB, matching MAX_BASELINE_BYTES).
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;

/// Maximum length of a baseline key in characters.
pub const MAX_KEY_LEN: usize = 128;

/// Errors raised during baseline synchronization.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BaselineSyncError {
    /// The supplied baseline key violates security constraints.
    #[error("invalid baseline key: {0}")]
    InvalidKey(String),

    /// The baseline envelope exceeds the maximum allowable size.
    #[error("baseline envelope is too large ({size} bytes; limit {limit} bytes)")]
    EnvelopeTooLarge { size: usize, limit: usize },

    /// The baseline envelope is not well-formed JSON.
    #[error("malformed baseline envelope: {0}")]
    MalformedEnvelope(String),

    /// The envelope schema version is not supported by this build.
    #[error("unsupported baseline envelope schema version {found} (supported: {supported})")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },

    /// The baseline was created against a different rule registry than the current build.
    #[error("baseline rule registry fingerprint mismatch: envelope has `{found}`, current build has `{expected}`")]
    RegistryFingerprintMismatch { found: String, expected: String },

    /// The payload content hash does not match the envelope declaration.
    #[error("baseline payload content hash mismatch: expected `{expected}`, calculated `{calculated}` (corrupted artifact)")]
    ContentHashMismatch {
        expected: String,
        calculated: String,
    },

    /// Overwrite refused because the remote baseline has a newer revision.
    #[error("refusing to overwrite newer remote baseline (remote revision {remote_revision} > local revision {local_revision}); pass --force to overwrite")]
    RefusedOverwriteNewer {
        remote_revision: u64,
        local_revision: u64,
    },

    /// Overwrite refused because baselines at the same revision have diverged.
    #[error("refusing to overwrite diverged remote baseline at revision {revision} (remote hash `{remote_hash}`, local hash `{local_hash}`); pass --force to overwrite")]
    RefusedOverwriteDiverged {
        revision: u64,
        remote_hash: String,
        local_hash: String,
    },

    /// An error occurred during store I/O or communication.
    #[error("baseline store error: {0}")]
    Store(String),

    /// Failed to parse the inner baseline payload.
    #[error("baseline parse error: {0}")]
    BaselineParse(String),

    /// Failed to serialize the baseline payload.
    #[error("baseline serialize error: {0}")]
    BaselineSerialize(String),

    /// Failed to serialize the baseline envelope.
    #[error("baseline envelope serialize error: {0}")]
    EnvelopeSerialize(String),

    /// File I/O failure.
    #[error("I/O error: {0}")]
    Io(String),
}

/// Validates that a baseline key conforms to security requirements:
/// - Non-empty
/// - Length <= [`MAX_KEY_LEN`]
/// - Permitted characters only: ASCII `[A-Za-z0-9._-]`
/// - No relative navigation (`.` or `..`)
pub fn validate_key(key: &str) -> Result<(), BaselineSyncError> {
    if key.is_empty() {
        return Err(BaselineSyncError::InvalidKey(
            "baseline key cannot be empty".to_string(),
        ));
    }
    if key.len() > MAX_KEY_LEN {
        return Err(BaselineSyncError::InvalidKey(format!(
            "baseline key is too long ({} characters; limit {} characters)",
            key.len(),
            MAX_KEY_LEN
        )));
    }
    if key == "." || key == ".." || key.contains("..") {
        return Err(BaselineSyncError::InvalidKey(format!(
            "baseline key `{key}` contains forbidden relative path component `..`"
        )));
    }
    for c in key.chars() {
        if !c.is_ascii_alphanumeric() && c != '.' && c != '_' && c != '-' {
            return Err(BaselineSyncError::InvalidKey(format!(
                "baseline key `{key}` contains invalid character `{c}`; only [A-Za-z0-9._-] are permitted"
            )));
        }
    }
    Ok(())
}

/// Computes a stable SHA-256 fingerprint of the current build's rule registry.
///
/// Iterates over all rules sorted by id, digesting the rule id and scanner version.
pub fn compute_registry_fingerprint(registry: &RuleRegistry) -> String {
    let mut hasher = Sha256::new();
    let sorted = registry.metadata_sorted();
    for meta in sorted {
        hasher.update(meta.id.as_bytes());
        hasher.update(b":");
        hasher.update(crate::VERSION.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Computes a SHA-256 hex digest for arbitrary bytes.
pub fn sha256_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Redacts sensitive token strings from text messages, error outputs, or logs.
pub fn redact_credentials(text: &str, sensitive_tokens: &[&str]) -> String {
    let mut result = text.to_string();
    for &token in sensitive_tokens {
        if !token.is_empty() {
            result = result.replace(token, "[REDACTED]");
        }
    }
    crate::ai::redact(&result)
}

/// A serialized envelope wrapping a baseline artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineEnvelope {
    /// Envelope schema version.
    pub schema_version: u32,
    /// Stable digest over sorted rule ids and versions for the producing build.
    pub registry_fingerprint: String,
    /// Monotonically increasing revision number.
    pub revision: u64,
    /// SHA-256 digest of `payload`.
    pub content_hash: String,
    /// Serialized baseline text (JSON).
    pub payload: String,
}

impl BaselineEnvelope {
    /// Creates a new envelope for the given baseline payload.
    pub fn new(registry_fingerprint: String, revision: u64, payload: String) -> Self {
        let content_hash = sha256_digest(payload.as_bytes());
        BaselineEnvelope {
            schema_version: CURRENT_ENVELOPE_SCHEMA_VERSION,
            registry_fingerprint,
            revision,
            content_hash,
            payload,
        }
    }

    /// Verifies envelope integrity and consistency in fail-closed order:
    /// 1. Bounded size limit (before parsing)
    /// 2. Well-formed JSON envelope structure
    /// 3. Supported schema version
    /// 4. Rule registry fingerprint match
    /// 5. Payload content hash verification
    /// 6. Inner baseline parsing
    pub fn verify_and_unpack(
        raw_bytes: &[u8],
        expected_registry_fingerprint: &str,
    ) -> Result<(Self, Baseline), BaselineSyncError> {
        // 1. Size limit check before parsing
        if raw_bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(BaselineSyncError::EnvelopeTooLarge {
                size: raw_bytes.len(),
                limit: MAX_ENVELOPE_BYTES,
            });
        }

        // 2. Well-formed envelope JSON
        let envelope: BaselineEnvelope = serde_json::from_slice(raw_bytes)
            .map_err(|e| BaselineSyncError::MalformedEnvelope(e.to_string()))?;

        // 3. Supported schema version
        if envelope.schema_version != CURRENT_ENVELOPE_SCHEMA_VERSION {
            return Err(BaselineSyncError::UnsupportedSchemaVersion {
                found: envelope.schema_version,
                supported: CURRENT_ENVELOPE_SCHEMA_VERSION,
            });
        }

        // 4. Registry fingerprint match
        if envelope.registry_fingerprint != expected_registry_fingerprint {
            return Err(BaselineSyncError::RegistryFingerprintMismatch {
                found: envelope.registry_fingerprint.clone(),
                expected: expected_registry_fingerprint.to_string(),
            });
        }

        // 5. Content hash match
        let calculated = sha256_digest(envelope.payload.as_bytes());
        if envelope.content_hash != calculated {
            return Err(BaselineSyncError::ContentHashMismatch {
                expected: envelope.content_hash.clone(),
                calculated,
            });
        }

        // 6. Inner baseline payload parsing
        let baseline = Baseline::from_text(&envelope.payload)
            .map_err(|e| BaselineSyncError::BaselineParse(e.to_string()))?;

        Ok((envelope, baseline))
    }
}

/// Storage abstraction for synchronizing baseline artifacts.
pub trait BaselineStore: Send + Sync {
    /// Fetches the raw artifact bytes stored under `key`.
    /// Returns `Ok(None)` if no baseline artifact exists for `key`.
    fn fetch(&self, key: &str) -> Result<Option<Vec<u8>>, BaselineSyncError>;

    /// Stores raw artifact `bytes` under `key`.
    fn store(&self, key: &str, bytes: &[u8]) -> Result<(), BaselineSyncError>;
}

/// In-memory mock store for testing and verification.
///
/// Records call counts so tests can verify opt-in behavior ("no calls when sync is disabled").
#[derive(Debug, Default)]
pub struct MockBaselineStore {
    artifacts: Mutex<HashMap<String, Vec<u8>>>,
    fetch_calls: AtomicUsize,
    store_calls: AtomicUsize,
}

impl MockBaselineStore {
    /// Creates a new empty mock store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of `fetch` invocations.
    pub fn fetch_count(&self) -> usize {
        self.fetch_calls.load(Ordering::SeqCst)
    }

    /// Number of `store` invocations.
    pub fn store_count(&self) -> usize {
        self.store_calls.load(Ordering::SeqCst)
    }

    /// Total number of store calls.
    pub fn total_calls(&self) -> usize {
        self.fetch_count() + self.store_count()
    }

    /// Resets call counters.
    pub fn reset_counts(&self) {
        self.fetch_calls.store(0, Ordering::SeqCst);
        self.store_calls.store(0, Ordering::SeqCst);
    }
}

impl BaselineStore for MockBaselineStore {
    fn fetch(&self, key: &str) -> Result<Option<Vec<u8>>, BaselineSyncError> {
        validate_key(key)?;
        self.fetch_calls.fetch_add(1, Ordering::SeqCst);
        let map = self.artifacts.lock().unwrap();
        Ok(map.get(key).cloned())
    }

    fn store(&self, key: &str, bytes: &[u8]) -> Result<(), BaselineSyncError> {
        validate_key(key)?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(BaselineSyncError::EnvelopeTooLarge {
                size: bytes.len(),
                limit: MAX_ENVELOPE_BYTES,
            });
        }
        self.store_calls.fetch_add(1, Ordering::SeqCst);
        let mut map = self.artifacts.lock().unwrap();
        map.insert(key.to_string(), bytes.to_vec());
        Ok(())
    }
}

/// Directory-backed store where the key maps to a file inside `root`.
///
/// Designed for CI workflows that transfer baseline state via `actions/upload-artifact`
/// + `actions/download-artifact` or `actions/cache`.
#[derive(Debug, Clone)]
pub struct DirectoryBaselineStore {
    root: PathBuf,
}

impl DirectoryBaselineStore {
    /// Creates a new store rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the root directory of this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves the filesystem path for `key`, enforcing path-traversal safety.
    pub fn path_for_key(&self, key: &str) -> Result<PathBuf, BaselineSyncError> {
        validate_key(key)?;
        Ok(self.root.join(format!("{key}.json")))
    }
}

impl BaselineStore for DirectoryBaselineStore {
    fn fetch(&self, key: &str) -> Result<Option<Vec<u8>>, BaselineSyncError> {
        let path = self.path_for_key(key)?;
        if !path.exists() {
            return Ok(None);
        }
        let metadata = std::fs::metadata(&path)
            .map_err(|e| BaselineSyncError::Io(format!("cannot read {}: {e}", path.display())))?;
        if metadata.len() > MAX_ENVELOPE_BYTES as u64 {
            return Err(BaselineSyncError::EnvelopeTooLarge {
                size: metadata.len() as usize,
                limit: MAX_ENVELOPE_BYTES,
            });
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| BaselineSyncError::Io(format!("cannot read {}: {e}", path.display())))?;
        Ok(Some(bytes))
    }

    fn store(&self, key: &str, bytes: &[u8]) -> Result<(), BaselineSyncError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(BaselineSyncError::EnvelopeTooLarge {
                size: bytes.len(),
                limit: MAX_ENVELOPE_BYTES,
            });
        }
        let path = self.path_for_key(key)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                BaselineSyncError::Io(format!(
                    "cannot create store directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
        std::fs::write(&path, bytes)
            .map_err(|e| BaselineSyncError::Io(format!("cannot write {}: {e}", path.display())))?;
        Ok(())
    }
}

/// Synchronizes a baseline to the store with monotonic revisioning and overwrite protection.
///
/// Comparison rules:
/// 1. If no remote baseline exists: store at revision 1 (or `explicit_revision`).
/// 2. If remote revision > local revision: refuse unless `force` is true.
/// 3. If remote revision == local revision with differing content hashes (diverged):
///    refuse unless `force` is true.
/// 4. If local revision > remote revision: store without confirmation.
/// 5. If remote revision == local revision with identical content hashes: idempotent write.
pub fn push_baseline<S: BaselineStore>(
    store: &S,
    key: &str,
    baseline: &Baseline,
    registry: &RuleRegistry,
    force: bool,
    explicit_revision: Option<u64>,
) -> Result<BaselineEnvelope, BaselineSyncError> {
    validate_key(key)?;

    let registry_fingerprint = compute_registry_fingerprint(registry);
    let payload = baseline
        .to_json()
        .map_err(|e| BaselineSyncError::BaselineSerialize(e.to_string()))?;
    let content_hash = sha256_digest(payload.as_bytes());

    let existing_remote = store.fetch(key)?;

    let target_revision = match (explicit_revision, &existing_remote) {
        (Some(rev), _) => rev,
        (None, None) => 1,
        (None, Some(bytes)) => {
            if bytes.len() > MAX_ENVELOPE_BYTES {
                if !force {
                    return Err(BaselineSyncError::EnvelopeTooLarge {
                        size: bytes.len(),
                        limit: MAX_ENVELOPE_BYTES,
                    });
                }
                1
            } else {
                match serde_json::from_slice::<BaselineEnvelope>(bytes) {
                    Ok(env) => env.revision.saturating_add(1),
                    Err(e) => {
                        if !force {
                            return Err(BaselineSyncError::MalformedEnvelope(format!(
                                "refusing to overwrite corrupted remote baseline: {e}; pass --force to overwrite"
                            )));
                        }
                        1
                    }
                }
            }
        }
    };

    let envelope = BaselineEnvelope {
        schema_version: CURRENT_ENVELOPE_SCHEMA_VERSION,
        registry_fingerprint,
        revision: target_revision,
        content_hash: content_hash.clone(),
        payload,
    };

    // Check overwrite protection against remote envelope if present
    if let Some(remote_bytes) = existing_remote {
        if remote_bytes.len() > MAX_ENVELOPE_BYTES {
            if !force {
                return Err(BaselineSyncError::EnvelopeTooLarge {
                    size: remote_bytes.len(),
                    limit: MAX_ENVELOPE_BYTES,
                });
            }
        } else {
            match serde_json::from_slice::<BaselineEnvelope>(&remote_bytes) {
                Ok(remote_env) => {
                    if !force {
                        if remote_env.revision > envelope.revision {
                            return Err(BaselineSyncError::RefusedOverwriteNewer {
                                remote_revision: remote_env.revision,
                                local_revision: envelope.revision,
                            });
                        }
                        if remote_env.revision == envelope.revision
                            && remote_env.content_hash != envelope.content_hash
                        {
                            return Err(BaselineSyncError::RefusedOverwriteDiverged {
                                revision: envelope.revision,
                                remote_hash: remote_env.content_hash,
                                local_hash: envelope.content_hash,
                            });
                        }
                    }
                }
                Err(e) => {
                    if !force {
                        return Err(BaselineSyncError::MalformedEnvelope(format!(
                            "refusing to overwrite corrupted remote baseline: {e}; pass --force to overwrite"
                        )));
                    }
                }
            }
        }
    }

    let serialized = serde_json::to_vec_pretty(&envelope)
        .map_err(|e| BaselineSyncError::EnvelopeSerialize(e.to_string()))?;
    store.store(key, &serialized)?;

    Ok(envelope)
}

/// Pulls and verifies a baseline artifact from the store.
///
/// Returns `Ok(None)` if no baseline is stored under `key`.
/// Returns an error if the envelope is invalid, corrupted, or incompatible.
pub fn pull_baseline<S: BaselineStore>(
    store: &S,
    key: &str,
    registry: &RuleRegistry,
) -> Result<Option<(BaselineEnvelope, Baseline)>, BaselineSyncError> {
    validate_key(key)?;
    let expected_fingerprint = compute_registry_fingerprint(registry);
    let bytes_opt = store.fetch(key)?;
    let Some(raw_bytes) = bytes_opt else {
        return Ok(None);
    };
    let (envelope, baseline) =
        BaselineEnvelope::verify_and_unpack(&raw_bytes, &expected_fingerprint)?;
    Ok(Some((envelope, baseline)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::confidence::Confidence;
    use crate::finding::{Finding, SourceLocation};
    use crate::rule::RuleMetadata;
    use crate::severity::Severity;

    fn sample_rule_meta(id: &'static str) -> RuleMetadata {
        RuleMetadata::new(
            id,
            "Test Rule",
            "Description of the rule for testing purposes",
            Category::Authorization,
            Severity::High,
            Confidence::Medium,
            "Remediation guidance",
        )
    }

    fn sample_finding(file: &str, line: usize, evidence: &str) -> Finding {
        Finding::new(
            &sample_rule_meta("SS-001"),
            SourceLocation::new(file, line),
            evidence,
        )
    }

    fn sample_baseline() -> Baseline {
        Baseline::from_findings(&[
            sample_finding("src/contract.rs", 12, "require_auth_missing"),
            sample_finding("src/token.rs", 45, "overflow_check_missing"),
        ])
    }

    #[test]
    fn test_round_trip_through_mock_store() {
        let registry = RuleRegistry::with_default_rules();
        let store = MockBaselineStore::new();
        let baseline = sample_baseline();

        let envelope =
            push_baseline(&store, "main-baseline", &baseline, &registry, false, None).unwrap();
        assert_eq!(envelope.revision, 1);
        assert_eq!(store.store_count(), 1);

        let pulled = pull_baseline(&store, "main-baseline", &registry).unwrap();
        assert!(pulled.is_some());
        let (pulled_env, pulled_baseline) = pulled.unwrap();

        assert_eq!(pulled_env, envelope);
        assert_eq!(pulled_baseline, baseline);
    }

    #[test]
    fn test_mismatched_schema_version_rejected() {
        let registry = RuleRegistry::with_default_rules();
        let fp = compute_registry_fingerprint(&registry);
        let baseline = sample_baseline();
        let payload = baseline.to_json().unwrap();
        let hash = sha256_digest(payload.as_bytes());

        let raw = serde_json::json!({
            "schema_version": 999,
            "registry_fingerprint": fp,
            "revision": 1,
            "content_hash": hash,
            "payload": payload,
        });
        let bytes = serde_json::to_vec(&raw).unwrap();

        let result = BaselineEnvelope::verify_and_unpack(&bytes, &fp);
        assert_eq!(
            result,
            Err(BaselineSyncError::UnsupportedSchemaVersion {
                found: 999,
                supported: CURRENT_ENVELOPE_SCHEMA_VERSION,
            })
        );
    }

    #[test]
    fn test_mismatched_rule_registry_rejected() {
        let registry = RuleRegistry::with_default_rules();
        let fp = compute_registry_fingerprint(&registry);
        let baseline = sample_baseline();
        let payload = baseline.to_json().unwrap();
        let hash = sha256_digest(payload.as_bytes());

        let raw = serde_json::json!({
            "schema_version": CURRENT_ENVELOPE_SCHEMA_VERSION,
            "registry_fingerprint": "different-registry-hash-0123456789",
            "revision": 1,
            "content_hash": hash,
            "payload": payload,
        });
        let bytes = serde_json::to_vec(&raw).unwrap();

        let result = BaselineEnvelope::verify_and_unpack(&bytes, &fp);
        assert_eq!(
            result,
            Err(BaselineSyncError::RegistryFingerprintMismatch {
                found: "different-registry-hash-0123456789".to_string(),
                expected: fp,
            })
        );
    }

    #[test]
    fn test_corrupted_payload_hash_mismatch_rejected() {
        let registry = RuleRegistry::with_default_rules();
        let fp = compute_registry_fingerprint(&registry);
        let baseline = sample_baseline();
        let payload = baseline.to_json().unwrap();

        let raw = serde_json::json!({
            "schema_version": CURRENT_ENVELOPE_SCHEMA_VERSION,
            "registry_fingerprint": fp,
            "revision": 1,
            "content_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "payload": payload,
        });
        let bytes = serde_json::to_vec(&raw).unwrap();

        let result = BaselineEnvelope::verify_and_unpack(&bytes, &fp);
        assert!(matches!(
            result,
            Err(BaselineSyncError::ContentHashMismatch { .. })
        ));
    }

    #[test]
    fn test_oversized_artifact_rejected_before_parsing() {
        let registry = RuleRegistry::with_default_rules();
        let fp = compute_registry_fingerprint(&registry);

        let huge_bytes = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        let result = BaselineEnvelope::verify_and_unpack(&huge_bytes, &fp);
        assert_eq!(
            result,
            Err(BaselineSyncError::EnvelopeTooLarge {
                size: MAX_ENVELOPE_BYTES + 1,
                limit: MAX_ENVELOPE_BYTES,
            })
        );
    }

    #[test]
    fn test_invalid_keys_rejected_before_io() {
        let invalid_cases = [
            ("", "empty"),
            ("   ", "whitespace"),
            ("key/with/slash", "slash"),
            ("key\\with\\backslash", "backslash"),
            ("..", "dot-dot"),
            ("../escape", "path-traversal"),
            ("foo..bar", "contains-dot-dot"),
            ("key:colon", "colon"),
            ("key with spaces", "spaces"),
            ("key$special", "special-char"),
        ];

        let store = MockBaselineStore::new();
        let baseline = sample_baseline();
        let registry = RuleRegistry::with_default_rules();

        for (invalid_key, desc) in invalid_cases {
            assert!(
                validate_key(invalid_key).is_err(),
                "case `{desc}` ({invalid_key}) should be rejected by validate_key"
            );
            assert!(
                push_baseline(&store, invalid_key, &baseline, &registry, false, None).is_err(),
                "case `{desc}` should be rejected by push_baseline"
            );
            assert!(
                pull_baseline(&store, invalid_key, &registry).is_err(),
                "case `{desc}` should be rejected by pull_baseline"
            );
        }

        // Test length cap
        let long_key = "a".repeat(MAX_KEY_LEN + 1);
        assert!(validate_key(&long_key).is_err());

        // Zero store calls must have occurred
        assert_eq!(store.total_calls(), 0);
    }

    #[test]
    fn test_overwrite_protection() {
        let registry = RuleRegistry::with_default_rules();
        let store = MockBaselineStore::new();
        let baseline1 = sample_baseline();
        let baseline2 = Baseline::from_findings(&[sample_finding("src/diff.rs", 1, "evidence")]);

        // 1. Initial push without remote: stored
        let env1 =
            push_baseline(&store, "branch-key", &baseline1, &registry, false, Some(5)).unwrap();
        assert_eq!(env1.revision, 5);

        // 2. Remote newer (remote 5 > local 3): refused without force
        let err =
            push_baseline(&store, "branch-key", &baseline1, &registry, false, Some(3)).unwrap_err();
        assert_eq!(
            err,
            BaselineSyncError::RefusedOverwriteNewer {
                remote_revision: 5,
                local_revision: 3,
            }
        );

        // 3. Remote newer, but with force: allowed
        let forced =
            push_baseline(&store, "branch-key", &baseline1, &registry, true, Some(3)).unwrap();
        assert_eq!(forced.revision, 3);

        // 4. Equal revision but different hash: refused without force
        let err_diverged =
            push_baseline(&store, "branch-key", &baseline2, &registry, false, Some(3)).unwrap_err();
        assert!(matches!(
            err_diverged,
            BaselineSyncError::RefusedOverwriteDiverged { .. }
        ));

        // 5. Equal revision but different hash, with force: allowed
        let forced_diverged =
            push_baseline(&store, "branch-key", &baseline2, &registry, true, Some(3)).unwrap();
        assert_eq!(forced_diverged.revision, 3);

        // 6. Local newer (local 4 > remote 3): allowed without force
        let newer =
            push_baseline(&store, "branch-key", &baseline2, &registry, false, Some(4)).unwrap();
        assert_eq!(newer.revision, 4);
    }

    #[test]
    fn test_missing_remote_baseline_on_pull_reported_distinctly() {
        let registry = RuleRegistry::with_default_rules();
        let store = MockBaselineStore::new();

        let result = pull_baseline(&store, "non-existent-key", &registry);
        assert_eq!(result, Ok(None));
    }

    #[test]
    fn test_opt_in_zero_store_calls_when_sync_not_invoked() {
        let store = MockBaselineStore::new();
        // Plain inspection of store without sync calls
        assert_eq!(store.fetch_count(), 0);
        assert_eq!(store.store_count(), 0);
        assert_eq!(store.total_calls(), 0);
    }

    #[test]
    fn test_directory_backed_store_round_trip_and_safety() {
        let temp_dir = tempfile::tempdir().unwrap();
        let store = DirectoryBaselineStore::new(temp_dir.path());
        let registry = RuleRegistry::with_default_rules();
        let baseline = sample_baseline();

        // Round trip
        let pushed =
            push_baseline(&store, "ci-cache-key", &baseline, &registry, false, None).unwrap();
        assert_eq!(pushed.revision, 1);

        let pulled = pull_baseline(&store, "ci-cache-key", &registry).unwrap();
        assert!(pulled.is_some());
        assert_eq!(pulled.unwrap().1, baseline);

        // Confirm key path is inside store directory
        let key_path = store.path_for_key("ci-cache-key").unwrap();
        assert!(key_path.starts_with(temp_dir.path()));
        assert!(key_path.exists());

        // Malicious key cannot write outside directory
        assert!(store.path_for_key("../outside").is_err());
        assert!(store.path_for_key("sub/dir").is_err());
    }

    #[test]
    fn test_redact_credentials_redacts_tokens() {
        let secret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
        let message = format!("Request failed with token {secret} on https://api.github.com");
        let redacted = redact_credentials(&message, &[secret]);
        assert!(!redacted.contains(secret));
        assert!(redacted.contains("[REDACTED]"));
    }
}
