//! Bounded, local index for discovering installed rule packs.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::manifest::PackManifest;

/// Current schema version for a registry index.
pub const PACK_REGISTRY_SCHEMA_VERSION: u32 = 1;
pub const MAX_REGISTRY_BYTES: usize = 1024 * 1024;
/// Maximum size of a pack manifest read while validating an index entry (10 MiB).
pub const MAX_REGISTRY_MANIFEST_BYTES: usize = 10 * 1024 * 1024;

/// Validated local index. Loading never contacts a network or executes pack code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackRegistry {
    root: PathBuf,
    entries: Vec<PackRegistryEntry>,
}

/// A validated pack entry exposed to callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackRegistryEntry {
    pub name: String,
    pub version: String,
    /// SHA-256 of the exact bytes in the referenced `pack.toml`.
    pub checksum: String,
    /// Manifest path relative to the registry index directory.
    pub manifest: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    schema_version: u32,
    packs: Vec<PackRegistryEntry>,
}

/// Errors returned for malformed, unsafe, or inconsistent registry indexes.
#[derive(Debug, thiserror::Error)]
pub enum PackRegistryError {
    #[error("cannot read {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("input at {path} exceeds the {limit}-byte limit")]
    TooLarge { path: String, limit: usize },
    #[error("invalid registry TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid registry: {0}")]
    Validation(String),
}

impl PackRegistry {
    /// Load and fully validate a local `registry.toml` index.
    pub fn load(path: &Path) -> Result<Self, PackRegistryError> {
        let bytes = read_bounded(path, MAX_REGISTRY_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|error| PackRegistryError::Validation(error.to_string()))?;
        let document: RegistryDocument = toml::from_str(text)?;
        if document.schema_version != PACK_REGISTRY_SCHEMA_VERSION {
            return Err(PackRegistryError::Validation(format!(
                "unsupported schema_version {}; supported version is 1",
                document.schema_version
            )));
        }

        let root = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let mut identities = HashSet::new();
        for entry in &document.packs {
            validate_entry(entry)?;
            if !identities.insert((entry.name.as_str(), entry.version.as_str())) {
                return Err(PackRegistryError::Validation(format!(
                    "duplicate pack {}@{}",
                    entry.name, entry.version
                )));
            }
            let manifest_path = resolve_manifest(&root, &entry.manifest)?;
            let manifest_bytes = read_bounded(&manifest_path, MAX_REGISTRY_MANIFEST_BYTES)?;
            let actual_checksum = format!(
                "sha256:{}",
                hex::encode(Sha256::digest(&manifest_bytes)),
            );
            if entry.checksum != actual_checksum {
                return Err(PackRegistryError::Validation(format!(
                    "checksum mismatch for pack {}@{}",
                    entry.name, entry.version
                )));
            }
            let manifest_text = std::str::from_utf8(&manifest_bytes)
                .map_err(|error| PackRegistryError::Validation(error.to_string()))?;
            let manifest = PackManifest::parse_str(manifest_text)
                .map_err(|error| PackRegistryError::Validation(error.to_string()))?;
            if manifest.pack.name != entry.name || manifest.pack.version != entry.version {
                return Err(PackRegistryError::Validation(format!(
                    "registry identity does not match manifest for {}@{}",
                    entry.name, entry.version
                )));
            }
        }

        Ok(Self {
            root,
            entries: document.packs,
        })
    }

    /// Return every validated entry, sorted by name and version.
    pub fn entries(&self) -> Vec<&PackRegistryEntry> {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|left, right| {
            (&left.name, &left.version).cmp(&(&right.name, &right.version))
        });
        entries
    }

    /// Find a validated pack by exact name and version.
    pub fn find(&self, name: &str, version: &str) -> Option<&PackRegistryEntry> {
        self.entries
            .iter()
            .find(|entry| entry.name == name && entry.version == version)
    }

    /// Return the local manifest path for a validated pack entry.
    pub fn manifest_path(&self, name: &str, version: &str) -> Option<PathBuf> {
        self.find(name, version)
            .map(|entry| self.root.join(&entry.manifest))
    }
}

fn validate_entry(entry: &PackRegistryEntry) -> Result<(), PackRegistryError> {
    if !valid_name(&entry.name) {
        return Err(PackRegistryError::Validation(format!(
            "invalid pack name {:?}",
            entry.name
        )));
    }
    if !valid_version(&entry.version) {
        return Err(PackRegistryError::Validation(format!(
            "invalid pack version {:?}",
            entry.version
        )));
    }
    let Some(digest) = entry.checksum.strip_prefix("sha256:") else {
        return Err(PackRegistryError::Validation(format!(
            "invalid checksum for {}@{}",
            entry.name, entry.version
        )));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(PackRegistryError::Validation(format!(
            "invalid checksum for {}@{}",
            entry.name, entry.version
        )));
    }
    if entry.manifest.is_empty() {
        return Err(PackRegistryError::Validation(
            "manifest path must not be empty".into(),
        ));
    }
    Ok(())
}

fn resolve_manifest(root: &Path, relative: &str) -> Result<PathBuf, PackRegistryError> {
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(PackRegistryError::Validation(format!(
            "manifest path must be a safe relative path: {relative:?}"
        )));
    }
    let canonical_root = fs::canonicalize(root).map_err(|source| PackRegistryError::Io {
        path: root.display().to_string(),
        source,
    })?;
    let unresolved_path = canonical_root.join(relative_path);
    let path = fs::canonicalize(&unresolved_path).map_err(|source| PackRegistryError::Io {
        path: unresolved_path.display().to_string(),
        source,
    })?;
    if !path.starts_with(&canonical_root) {
        return Err(PackRegistryError::Validation(format!(
            "manifest path escapes registry directory: {relative:?}"
        )));
    }
    Ok(path)
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, PackRegistryError> {
    let file = fs::File::open(path).map_err(|source| PackRegistryError::Io {
        path: path.display().to_string(),
        source,
    })?;
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| PackRegistryError::Io {
            path: path.display().to_string(),
            source,
        })?;
    if bytes.len() > limit {
        return Err(PackRegistryError::TooLarge {
            path: path.display().to_string(),
            limit,
        });
    }
    Ok(bytes)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn valid_version(version: &str) -> bool {
    let mut parts = version.split('.');
    (0..3).all(|_| {
        parts.next().is_some_and(|part| {
            !part.is_empty()
                && !(part.len() > 1 && part.starts_with('0'))
                && part.bytes().all(|byte| byte.is_ascii_digit())
        })
    }) && parts.next().is_none()
}
