//! Versioned rule-pack manifest schema and compatibility tests.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use soroban_scan_core::pack::{
    KeyRing, PackCapability, PackLoadError, PackLoader, PackManifest, PackManifestError,
    PackVerificationError, PackVerifier, VerificationPolicy, MAX_PACK_MANIFEST_BYTES,
    SCANNER_CAPABILITIES,
};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

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
    assert_eq!(
        manifest.check_compatibility("0.1.9", &[PackCapability::RustSourceAnalysis]),
        Err(PackManifestError::ScannerVersionBelowMinimum {
            current: "0.1.9".to_string(),
            required: "0.2.0".to_string(),
        })
    );
    assert_eq!(
        manifest.check_compatibility("0.2.0", &[PackCapability::CargoManifestAnalysis]),
        Err(PackManifestError::MissingCapability {
            capability: "rust_source_analysis".to_string(),
        })
    );

    let mut bounded = manifest.clone();
    bounded.pack.max_scanner_version = Some("0.2.9".to_string());
    assert_eq!(
        bounded.check_compatibility("0.3.0", &[PackCapability::RustSourceAnalysis]),
        Err(PackManifestError::ScannerVersionAboveMaximum {
            current: "0.3.0".to_string(),
            maximum: "0.2.9".to_string(),
        })
    );
    assert!(bounded
        .check_compatibility("0.2.9", &[PackCapability::RustSourceAnalysis])
        .is_ok());
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

    let result =
        PackVerifier::verify_pack_dir(&dir, &KeyRing::new(), VerificationPolicy::AllowUnsigned);
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

fn temp_pack_dir(manifest: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "soroban-pack-compat-{}-{}",
        std::process::id(),
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temporary pack directory");
    fs::write(dir.join("pack.toml"), manifest).expect("write pack manifest");
    dir
}

#[test]
fn scanner_capability_list_is_explicit_and_bounded() {
    assert_eq!(
        SCANNER_CAPABILITIES,
        &[
            PackCapability::RustSourceAnalysis,
            PackCapability::CargoManifestAnalysis,
        ]
    );
}

#[test]
fn loader_enforces_the_declared_version_range() {
    let bounded = sample_manifest_text().replace(
        "min_scanner_version = \"0.2.0\"",
        "min_scanner_version = \"0.2.0\"\nmax_scanner_version = \"0.2.9\"",
    );
    let dir = temp_pack_dir(&bounded);
    let keyring = KeyRing::new();

    let too_new = PackLoader::load_dir_for_version(
        &dir,
        &keyring,
        VerificationPolicy::AllowUnsigned,
        "0.3.0",
    )
    .expect_err("a scanner above the declared maximum must be rejected");
    match too_new {
        PackLoadError::IncompatibleScannerVersionMaximum { maximum, current } => {
            assert_eq!(maximum, "0.2.9");
            assert_eq!(current, "0.3.0");
        }
        other => panic!("expected IncompatibleScannerVersionMaximum, got {other:?}"),
    }

    let accepted = PackLoader::load_dir_for_version(
        &dir,
        &keyring,
        VerificationPolicy::AllowUnsigned,
        "0.2.5",
    )
    .expect("a scanner inside the declared range must load");
    assert_eq!(accepted.manifest.pack.name, "soroban-defi-rules");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn loader_rejects_below_minimum_with_the_existing_clear_error() {
    let dir = temp_pack_dir(sample_manifest_text());
    let keyring = KeyRing::new();
    let too_old = PackLoader::load_dir_for_version(
        &dir,
        &keyring,
        VerificationPolicy::AllowUnsigned,
        "0.1.9",
    )
    .expect_err("a scanner below the declared minimum must be rejected");
    assert_eq!(
        too_old,
        PackLoadError::IncompatibleScannerVersion {
            required: "0.2.0".to_string(),
            current: "0.1.9".to_string(),
        }
    );
    let _ = fs::remove_dir_all(&dir);
}
