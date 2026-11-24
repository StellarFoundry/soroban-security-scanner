//! Safe rule pack loading and compatibility validation.
//!
//! Loading an external rule pack is opt-in, bounded in size and rule count,
//! and fails closed when a pack is unsigned (unless explicitly allowed),
//! tampered, malformed, unsafe on disk, or targets a newer scanner version.

use std::collections::BTreeSet;
use std::path::Path;

use crate::pack::manifest::PackManifest;
use crate::pack::signing::{
    DetachedSignature, KeyRing, PackVerificationError, PackVerifier, VerificationPolicy,
    VerificationResult,
};

/// Maximum allowed size of `pack.toml` in bytes (1 MiB).
pub const MAX_PACK_MANIFEST_SIZE: usize = 1024 * 1024;

/// Maximum allowed size of `pack.sig` in bytes (64 KiB).
pub const MAX_PACK_SIGNATURE_SIZE: usize = 64 * 1024;

/// Maximum number of rules permitted in a single rule pack.
pub const MAX_PACK_RULES: usize = 256;

/// Maximum length of a pack name in bytes.
pub const MAX_PACK_NAME_LEN: usize = 128;

/// A validated, verified rule pack loaded from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedPack {
    /// Parsed and validated pack manifest.
    pub manifest: PackManifest,
    /// Cryptographic verification outcome.
    pub verification: VerificationResult,
}

/// Errors raised when safely loading a rule pack.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackLoadError {
    /// Filesystem I/O failure while reading the pack.
    #[error("io error loading pack: {0}")]
    Io(String),

    /// Pack directory or file failed safety checks (e.g. symlink or non-regular file).
    #[error("unsafe pack path: {0}")]
    UnsafePath(String),

    /// A pack file exceeded its bounded size limit.
    #[error("pack file '{path}' exceeds size limit of {max_bytes} bytes")]
    PayloadTooLarge { path: String, max_bytes: usize },

    /// Signature verification failed under the active policy.
    #[error(transparent)]
    Verification(#[from] PackVerificationError),

    /// `pack.toml` could not be parsed as a valid manifest.
    #[error("invalid pack manifest: {0}")]
    InvalidManifest(String),

    /// Pack metadata or rule declarations failed validation.
    #[error("invalid pack metadata: {0}")]
    InvalidMetadata(String),

    /// Pack requires a newer scanner version than the running binary.
    #[error(
        "incompatible scanner version: pack requires >= {required}, current scanner is {current}"
    )]
    IncompatibleScannerVersion { required: String, current: String },
}

/// Safe, bounded loader for rule pack directories.
pub struct PackLoader;

impl PackLoader {
    /// Safely verifies, loads, and validates a rule pack directory against
    /// [`crate::VERSION`].
    pub fn load_dir(
        dir: &Path,
        keyring: &KeyRing,
        policy: VerificationPolicy,
    ) -> Result<LoadedPack, PackLoadError> {
        Self::load_dir_for_version(dir, keyring, policy, crate::VERSION)
    }

    /// Safely verifies, loads, and validates a rule pack directory against an
    /// explicit scanner version string.
    pub fn load_dir_for_version(
        dir: &Path,
        keyring: &KeyRing,
        policy: VerificationPolicy,
        scanner_version: &str,
    ) -> Result<LoadedPack, PackLoadError> {
        let dir_meta = std::fs::symlink_metadata(dir).map_err(|e| {
            PackLoadError::Io(format!(
                "cannot access pack directory {}: {e}",
                dir.display()
            ))
        })?;
        if dir_meta.file_type().is_symlink() || !dir_meta.is_dir() {
            return Err(PackLoadError::UnsafePath(format!(
                "{} must be a regular directory",
                dir.display()
            )));
        }

        let manifest_path = dir.join("pack.toml");
        let manifest_bytes = read_regular_bounded(&manifest_path, MAX_PACK_MANIFEST_SIZE)?;

        let sig_path = dir.join("pack.sig");
        let detached_sig = match std::fs::symlink_metadata(&sig_path) {
            Ok(_) => {
                let sig_bytes = read_regular_bounded(&sig_path, MAX_PACK_SIGNATURE_SIZE)?;
                let sig_text = std::str::from_utf8(&sig_bytes).map_err(|e| {
                    PackVerificationError::MalformedSignature(format!(
                        "non-UTF-8 signature in {}: {e}",
                        sig_path.display()
                    ))
                })?;
                Some(DetachedSignature::from_toml(sig_text).map_err(|e| {
                    PackVerificationError::MalformedSignature(format!(
                        "invalid TOML in {}: {e}",
                        sig_path.display()
                    ))
                })?)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(PackLoadError::Io(format!(
                    "cannot inspect {}: {e}",
                    sig_path.display()
                )));
            }
        };

        let verification =
            PackVerifier::verify(&manifest_bytes, detached_sig.as_ref(), keyring, policy)?;

        let manifest_text = std::str::from_utf8(&manifest_bytes)
            .map_err(|e| PackLoadError::InvalidManifest(format!("non-UTF-8 pack.toml: {e}")))?;
        let manifest = PackManifest::parse_str(manifest_text)
            .map_err(|e| PackLoadError::InvalidManifest(e.to_string()))?;

        validate_manifest(&manifest, scanner_version)?;

        Ok(LoadedPack {
            manifest,
            verification,
        })
    }
}

fn read_regular_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, PackLoadError> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| PackLoadError::Io(format!("cannot access {}: {e}", path.display())))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(PackLoadError::UnsafePath(format!(
            "{} must be a regular file (symlinks are rejected)",
            path.display()
        )));
    }
    if meta.len() > max_bytes as u64 {
        return Err(PackLoadError::PayloadTooLarge {
            path: path.display().to_string(),
            max_bytes,
        });
    }
    let bytes = std::fs::read(path)
        .map_err(|e| PackLoadError::Io(format!("cannot read {}: {e}", path.display())))?;
    if bytes.len() > max_bytes {
        return Err(PackLoadError::PayloadTooLarge {
            path: path.display().to_string(),
            max_bytes,
        });
    }
    Ok(bytes)
}

/// Validates pack metadata, rule declarations, and scanner compatibility.
pub fn validate_manifest(
    manifest: &PackManifest,
    scanner_version: &str,
) -> Result<(), PackLoadError> {
    let name = manifest.pack.name.trim();
    if name.is_empty() || name.len() > MAX_PACK_NAME_LEN {
        return Err(PackLoadError::InvalidMetadata(format!(
            "pack.name must be 1..={MAX_PACK_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        || name == "."
        || name == ".."
    {
        return Err(PackLoadError::InvalidMetadata(format!(
            "pack.name '{}' contains disallowed characters",
            manifest.pack.name
        )));
    }

    parse_semver(&manifest.pack.version).ok_or_else(|| {
        PackLoadError::InvalidMetadata(format!(
            "invalid pack.version '{}' (expected MAJOR.MINOR.PATCH)",
            manifest.pack.version
        ))
    })?;

    if let Some(required) = &manifest.pack.min_scanner_version {
        let req_ver = parse_semver(required).ok_or_else(|| {
            PackLoadError::InvalidMetadata(format!(
                "invalid pack.min_scanner_version '{required}' (expected MAJOR.MINOR.PATCH)"
            ))
        })?;
        let cur_ver = parse_semver(scanner_version).ok_or_else(|| {
            PackLoadError::InvalidMetadata(format!(
                "invalid current scanner version '{scanner_version}'"
            ))
        })?;
        if req_ver > cur_ver {
            return Err(PackLoadError::IncompatibleScannerVersion {
                required: required.clone(),
                current: scanner_version.to_string(),
            });
        }
    }

    if manifest.rules.is_empty() {
        return Err(PackLoadError::InvalidMetadata(
            "pack must declare at least one rule".to_string(),
        ));
    }
    if manifest.rules.len() > MAX_PACK_RULES {
        return Err(PackLoadError::InvalidMetadata(format!(
            "pack declares {} rules, exceeding limit of {MAX_PACK_RULES}",
            manifest.rules.len()
        )));
    }

    let mut seen_ids = BTreeSet::new();
    for rule in &manifest.rules {
        let id = rule.id.trim();
        if id.is_empty()
            || id.len() > 64
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        {
            return Err(PackLoadError::InvalidMetadata(format!(
                "invalid rule id '{}'",
                rule.id
            )));
        }
        if !seen_ids.insert(id) {
            return Err(PackLoadError::InvalidMetadata(format!(
                "duplicate rule id '{id}'"
            )));
        }
        if rule.title.trim().is_empty() {
            return Err(PackLoadError::InvalidMetadata(format!(
                "rule '{id}' has empty title"
            )));
        }
        if rule.category.trim().is_empty() {
            return Err(PackLoadError::InvalidMetadata(format!(
                "rule '{id}' has empty category"
            )));
        }
        if rule.description.trim().is_empty() {
            return Err(PackLoadError::InvalidMetadata(format!(
                "rule '{id}' has empty description"
            )));
        }
        if let Some(checksum) = &rule.checksum {
            if checksum.len() != 64 || !checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(PackLoadError::InvalidMetadata(format!(
                    "rule '{id}' has invalid sha256 checksum '{checksum}'"
                )));
            }
        }
    }

    Ok(())
}

fn parse_semver(version: &str) -> Option<(u64, u64, u64)> {
    let core = version.trim().split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next()?.parse::<u64>().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}
