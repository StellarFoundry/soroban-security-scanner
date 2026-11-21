//! Versioned rule-pack manifest schema and compatibility tests.

use std::fs;
use std::path::PathBuf;

use soroban_scan_core::pack::{
    KeyRing, PackCapability, PackManifest, PackManifestError, PackVerificationError, PackVerifier,
    VerificationPolicy, MAX_PACK_MANIFEST_BYTES,
};

fn sample_manifest_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rule-packs/sample/pack.toml")
}

fn sample_manifest_text() -> &'static str {
    include_str!("../../../fixtures/rule-packs/sample/pack.toml")
}

#[test]
fn sample_pack_loads_and_checks_compatibility() {
    let manifest = PackManifest::load_file(&sample_manifest_path()).expect("sample pack loads");
    assert_eq!(manifest.schema_version, 1);
    assert_eq!(manifest.rules.len(), 1);
    assert_eq!(manifest.rules[0].id, "COMM-001");
    assert_eq!(
        manifest.rules[0].checksum,
        manifest.rules[0].expected_checksum()
    );
    assert!(manifest
        .check_compatibility(
            "0.2.0",
            &[
                PackCapability::RustSourceAnalysis,
                PackCapability::CargoManifestAnalysis
            ],
        )
        .is_ok());
}

#[test]
fn rejects_unsupported_schema_versions() {
    let text = sample_manifest_text().replace("schema_version = 1", "schema_version = 2");
    assert!(matches!(
        PackManifest::parse_str(&text),
        Err(PackManifestError::Validation(message)) if message.contains("unsupported schema_version")
    ));
}

#[test]
fn rejects_checksum_mismatches() {
    let text = sample_manifest_text().replace("unconstrained or zero.", "unconstrained or zero!.");
    assert!(matches!(
        PackManifest::parse_str(&text),
        Err(PackManifestError::Validation(message)) if message.contains("checksum mismatch")
    ));
}

#[test]
fn rejects_unknown_capabilities_and_fields() {
    let unknown_capability =
        sample_manifest_text().replace("rust_source_analysis", "arbitrary_code_execution");
    assert!(matches!(
        PackManifest::parse_str(&unknown_capability),
        Err(PackManifestError::Parse(_))
    ));

    let unknown_field = sample_manifest_text().replace(
        "schema_version = 1",
        "schema_version = 1\nexec = \"run-me\"",
    );
    assert!(matches!(
        PackManifest::parse_str(&unknown_field),
        Err(PackManifestError::Parse(_))
    ));
}

#[test]
fn compatibility_checks_minimum_maximum_and_required_capabilities() {
    let manifest = PackManifest::parse_str(sample_manifest_text()).unwrap();
    assert!(manifest
        .check_compatibility("0.1.9", &[PackCapability::RustSourceAnalysis])
        .is_err());
    assert!(manifest
        .check_compatibility("0.2.0", &[PackCapability::CargoManifestAnalysis])
        .is_err());

    let mut bounded = manifest.clone();
    bounded.pack.max_scanner_version = Some("0.2.9".to_string());
    assert!(bounded
        .check_compatibility("0.3.0", &[PackCapability::RustSourceAnalysis])
        .is_err());
}

#[test]
fn rejects_inverted_compatibility_ranges_and_duplicate_entries() {
    let mut manifest = PackManifest::parse_str(sample_manifest_text()).unwrap();
    manifest.pack.max_scanner_version = Some("0.1.9".to_string());
    assert!(manifest.validate().is_err());

    let mut manifest = PackManifest::parse_str(sample_manifest_text()).unwrap();
    manifest
        .pack
        .capabilities
        .push(PackCapability::RustSourceAnalysis);
    assert!(manifest.validate().is_err());

    let mut manifest = PackManifest::parse_str(sample_manifest_text()).unwrap();
    manifest.rules.push(manifest.rules[0].clone());
    assert!(manifest.validate().is_err());
}

#[test]
fn pack_directory_verification_rejects_invalid_schema() {
    let dir = std::env::temp_dir().join(format!("soroban-pack-schema-{}", std::process::id()));
    fs::create_dir(&dir).expect("create temporary pack directory");
    let invalid = sample_manifest_text().replace("schema_version = 1", "schema_version = 99");
    fs::write(dir.join("pack.toml"), invalid).expect("write invalid manifest");

    let result = PackVerifier::verify_pack_dir(
        &dir,
        &KeyRing::new(),
        VerificationPolicy::AllowUnsigned,
    );
    fs::remove_dir_all(&dir).expect("remove temporary pack directory");
    assert!(matches!(
        result,
        Err(PackVerificationError::MalformedManifest(_))
    ));
}

#[test]
fn manifest_size_is_bounded_before_parsing() {
    let oversized = " ".repeat(MAX_PACK_MANIFEST_BYTES + 1);
    assert_eq!(
        PackManifest::parse_str(&oversized),
        Err(PackManifestError::TooLarge)
    );
}
