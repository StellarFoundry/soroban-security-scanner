//! Local rule-pack registry validation and discovery tests.

use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use soroban_scan_core::pack::{PackRegistry, PackRegistryError};

fn fixture_registry() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rule-packs/registry.toml")
}

fn checksum(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn write_registry(
    root: &std::path::Path,
    manifest: &str,
    entry_name: &str,
    entry_version: &str,
    entry_path: &str,
) {
    fs::create_dir_all(root.join("packs")).unwrap();
    fs::write(root.join("packs/pack.toml"), manifest).unwrap();
    let digest = checksum(manifest.as_bytes());
    let index = format!(
        "schema_version = 1\n\n[[packs]]\nname = {entry_name:?}\nversion = {entry_version:?}\nchecksum = {digest:?}\nmanifest = {entry_path:?}\n"
    );
    fs::write(root.join("registry.toml"), index).unwrap();
}

const MANIFEST: &str = r#"[pack]
name = "sample-pack"
version = "1.2.3"
min_scanner_version = "0.1.0"

[[rules]]
id = "SAMP-001"
title = "Sample"
category = "test"
default_severity = "low"
default_confidence = "medium"
description = "A sample rule."
"#;

#[test]
fn sample_registry_discovers_and_resolves_installed_packs() {
    let registry = PackRegistry::load(&fixture_registry()).expect("sample registry validates");
    let entries = registry.entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "soroban-defi-rules");
    assert!(registry.find("soroban-defi-rules", "0.1.0").is_some());
    assert!(registry.find("missing", "0.0.1").is_none());
    assert!(registry
        .manifest_path("soroban-defi-rules", "0.1.0")
        .unwrap()
        .is_file());
}

#[test]
fn rejects_checksum_and_manifest_identity_mismatches() {
    let root =
        std::env::temp_dir().join(format!("soroban-registry-{}-checksum", std::process::id()));
    write_registry(&root, MANIFEST, "sample-pack", "1.2.3", "packs/pack.toml");
    let index = fs::read_to_string(root.join("registry.toml")).unwrap();
    fs::write(
        root.join("registry.toml"),
        index.replace(
            &checksum(MANIFEST.as_bytes()),
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
    )
    .unwrap();
    assert!(matches!(
        PackRegistry::load(&root.join("registry.toml")),
        Err(PackRegistryError::Validation(_))
    ));

    write_registry(&root, MANIFEST, "other-pack", "1.2.3", "packs/pack.toml");
    assert!(matches!(
        PackRegistry::load(&root.join("registry.toml")),
        Err(PackRegistryError::Validation(_))
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unsafe_paths_invalid_metadata_duplicates_and_unknown_fields() {
    let root =
        std::env::temp_dir().join(format!("soroban-registry-{}-invalid", std::process::id()));
    write_registry(&root, MANIFEST, "sample-pack", "1.2.3", "../outside.toml");
    assert!(matches!(
        PackRegistry::load(&root.join("registry.toml")),
        Err(PackRegistryError::Validation(_))
    ));

    write_registry(&root, MANIFEST, "../escape", "1.2.3", "packs/pack.toml");
    assert!(matches!(
        PackRegistry::load(&root.join("registry.toml")),
        Err(PackRegistryError::Validation(_))
    ));

    write_registry(&root, MANIFEST, "sample-pack", "1.2.3", "packs/pack.toml");
    let index = fs::read_to_string(root.join("registry.toml")).unwrap();
    let duplicate = format!("{}\n{}", index, &index[index.find("[[packs]]").unwrap()..]);
    fs::write(root.join("registry.toml"), duplicate).unwrap();
    assert!(matches!(
        PackRegistry::load(&root.join("registry.toml")),
        Err(PackRegistryError::Validation(_))
    ));

    fs::write(
        root.join("registry.toml"),
        "schema_version = 1\nexec = \"run\"\n",
    )
    .unwrap();
    assert!(matches!(
        PackRegistry::load(&root.join("registry.toml")),
        Err(PackRegistryError::Parse(_))
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_unsupported_schema_and_oversized_index() {
    let root =
        std::env::temp_dir().join(format!("soroban-registry-{}-bounded", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let path = root.join("registry.toml");
    fs::write(&path, "schema_version = 2\npacks = []\n").unwrap();
    assert!(matches!(
        PackRegistry::load(&path),
        Err(PackRegistryError::Validation(_))
    ));
    fs::write(
        &path,
        vec![b' '; soroban_scan_core::pack::registry::MAX_REGISTRY_BYTES + 1],
    )
    .unwrap();
    assert!(matches!(
        PackRegistry::load(&path),
        Err(PackRegistryError::TooLarge { .. })
    ));
    fs::remove_dir_all(root).unwrap();
}
