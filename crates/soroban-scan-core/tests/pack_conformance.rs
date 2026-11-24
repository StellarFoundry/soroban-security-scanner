//! Rule pack conformance integration tests (Issue #368).
//!
//! Verifies that:
//! - A signed conformance fixture pack loads safely and produces its known findings
//!   against the current scanner.
//! - Broken, tampered, unsigned, incompatible, oversized, or path-escaping packs
//!   fail clearly and safely.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use soroban_scan_core::pack::{
    ConformanceError, ConformanceRunner, KeyRing, KeyStatus, PackLoadError, PackLoader, PackSigner,
    PackVerificationError, TrustedKey, VerificationPolicy, MAX_PACK_MANIFEST_SIZE,
};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rule-packs")
}

fn deterministic_keypair(seed_byte: u8, key_id: &str) -> (SigningKey, TrustedKey) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    (sk, TrustedKey::new(key_id, pk_hex))
}

fn setup_test_keyring() -> (KeyRing, SigningKey) {
    let mut keyring = KeyRing::new();

    let (sk_active, key_active) = deterministic_keypair(10, "stellar-foundry-active");
    keyring.add_key(key_active);

    let (_sk_revoked, mut key_revoked) = deterministic_keypair(12, "compromised-key-2026");
    key_revoked.status = KeyStatus::Revoked;
    key_revoked.revocation_reason = Some("Key leaked in public CI log on 2026-05-01".to_string());
    keyring.add_key(key_revoked);

    (keyring, sk_active)
}

fn temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("soroban-pack-conformance-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn conformance_fixture_pack_passes_against_current_scanner() {
    let (keyring, _) = setup_test_keyring();
    let pack_dir = fixtures_root().join("conformance-valid");

    let report = ConformanceRunner::run(&pack_dir, &keyring, VerificationPolicy::EnforceSigned)
        .expect("conformance-valid fixture pack must pass");

    assert_eq!(report.pack.manifest.pack.name, "soroban-conformance-pack");
    assert_eq!(report.matched_expectations, 2);
    assert!(report.total_findings >= 2);
}

#[test]
fn broken_manifest_pack_fails_clearly() {
    let (keyring, _) = setup_test_keyring();
    let pack_dir = fixtures_root().join("broken-manifest");

    let err = PackLoader::load_dir(&pack_dir, &keyring, VerificationPolicy::AllowUnsigned)
        .expect_err("broken-manifest must fail");

    assert!(
        matches!(err, PackLoadError::InvalidManifest(_)),
        "expected InvalidManifest, got: {err:?}"
    );
}

#[test]
fn incompatible_scanner_version_pack_fails_clearly() {
    let (keyring, _) = setup_test_keyring();
    let pack_dir = fixtures_root().join("incompatible-version");

    let err = PackLoader::load_dir(&pack_dir, &keyring, VerificationPolicy::EnforceSigned)
        .expect_err("incompatible-version must fail");

    match err {
        PackLoadError::IncompatibleScannerVersion { required, current } => {
            assert_eq!(required, "99.0.0");
            assert_eq!(current, soroban_scan_core::VERSION);
        }
        other => panic!("expected IncompatibleScannerVersion, got: {other:?}"),
    }
}

#[test]
fn broken_expectations_pack_fails_clearly() {
    let (keyring, _) = setup_test_keyring();
    let pack_dir = fixtures_root().join("broken-expectations");

    let err = ConformanceRunner::run(&pack_dir, &keyring, VerificationPolicy::EnforceSigned)
        .expect_err("broken-expectations must fail");

    assert!(
        matches!(
            err,
            ConformanceError::MissingExpectedFinding {
                ref rule_id,
                expected_min: 1,
                actual: 0,
                ..
            } if rule_id == "SS-999"
        ),
        "expected MissingExpectedFinding for SS-999, got: {err:?}"
    );
}

#[test]
fn untrusted_tampered_unsigned_and_revoked_packs_fail_clearly() {
    let (keyring, _) = setup_test_keyring();

    let tampered = PackLoader::load_dir(
        &fixtures_root().join("tampered"),
        &keyring,
        VerificationPolicy::EnforceSigned,
    )
    .expect_err("tampered pack must fail");
    assert!(matches!(
        tampered,
        PackLoadError::Verification(PackVerificationError::SignatureMismatch(_))
    ));

    let unsigned = PackLoader::load_dir(
        &fixtures_root().join("unsigned"),
        &keyring,
        VerificationPolicy::EnforceSigned,
    )
    .expect_err("unsigned pack must fail under EnforceSigned");
    assert!(matches!(
        unsigned,
        PackLoadError::Verification(PackVerificationError::UnsignedPack)
    ));

    let revoked = PackLoader::load_dir(
        &fixtures_root().join("revoked-key"),
        &keyring,
        VerificationPolicy::EnforceSigned,
    )
    .expect_err("revoked-key pack must fail");
    assert!(matches!(
        revoked,
        PackLoadError::Verification(PackVerificationError::RevokedKey { .. })
    ));

    let untrusted = PackLoader::load_dir(
        &fixtures_root().join("untrusted-key"),
        &keyring,
        VerificationPolicy::EnforceSigned,
    )
    .expect_err("untrusted-key pack must fail");
    assert!(matches!(
        untrusted,
        PackLoadError::Verification(PackVerificationError::UnknownKey(_))
    ));
}

#[test]
fn oversized_manifest_is_rejected() {
    let (keyring, _) = setup_test_keyring();
    let dir = temp_dir("oversized");
    let big = vec![b'#'; MAX_PACK_MANIFEST_SIZE + 1];
    std::fs::write(dir.join("pack.toml"), big).unwrap();

    let err = PackLoader::load_dir(&dir, &keyring, VerificationPolicy::AllowUnsigned)
        .expect_err("oversized manifest must be rejected");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        matches!(err, PackLoadError::PayloadTooLarge { .. }),
        "expected PayloadTooLarge, got: {err:?}"
    );
}

#[test]
fn duplicate_rule_ids_are_rejected() {
    let (keyring, sk_active) = setup_test_keyring();
    let dir = temp_dir("dup-rules");
    let manifest = r#"schema_version = 1

[pack]
name = "dup-rules-pack"
version = "0.1.0"
min_scanner_version = "0.2.0"
capabilities = ["rust_source_analysis"]

[[rules]]
id = "DUP-001"
title = "First"
category = "testing"
default_severity = "low"
default_confidence = "low"
description = "First rule"
checksum = "sha256:3d08ad53d32bdebae9ec14a94a5261ee26f7bfda75e8a35dde73a5eb6cc674d3"

[[rules]]
id = "DUP-001"
title = "Duplicate"
category = "testing"
default_severity = "low"
default_confidence = "low"
description = "Duplicate rule"
checksum = "sha256:39143b33ecbaefbf4f5a11e266013b7b3dc64bd655d14a2428492c7b9d1ba2ed"
"#;
    let sig = PackSigner::sign("stellar-foundry-active", &sk_active, manifest.as_bytes());
    std::fs::write(dir.join("pack.toml"), manifest).unwrap();
    std::fs::write(dir.join("pack.sig"), sig.to_toml().unwrap()).unwrap();

    let err = PackLoader::load_dir(&dir, &keyring, VerificationPolicy::EnforceSigned)
        .expect_err("duplicate rule IDs must be rejected");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        matches!(err, PackLoadError::InvalidManifest(ref msg) if msg.contains("duplicate rule id")),
        "expected InvalidManifest for duplicate rule id, got: {err:?}"
    );
}

#[test]
fn path_traversal_in_conformance_target_is_rejected() {
    let (keyring, sk_active) = setup_test_keyring();
    let dir = temp_dir("path-traversal");
    let manifest = r#"schema_version = 1

[pack]
name = "traversal-pack"
version = "0.1.0"
min_scanner_version = "0.2.0"
capabilities = ["rust_source_analysis"]

[[rules]]
id = "TRAV-001"
title = "Traversal test"
category = "testing"
default_severity = "low"
default_confidence = "low"
description = "Tests path traversal rejection."
checksum = "sha256:cd3b8df86678b7b8e03c3e5d59f969f782f0be78e03d8cbdf52bff2c3bc1cdca"
"#;
    let sig = PackSigner::sign("stellar-foundry-active", &sk_active, manifest.as_bytes());
    std::fs::write(dir.join("pack.toml"), manifest).unwrap();
    std::fs::write(dir.join("pack.sig"), sig.to_toml().unwrap()).unwrap();
    std::fs::write(
        dir.join("conformance.toml"),
        "target = \"../outside\"\n\n[[expected_findings]]\nrule_id = \"SS-001\"\n",
    )
    .unwrap();

    let err = ConformanceRunner::run(&dir, &keyring, VerificationPolicy::EnforceSigned)
        .expect_err("path traversal target must be rejected");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        matches!(err, ConformanceError::UnsafeTarget(_)),
        "expected UnsafeTarget, got: {err:?}"
    );
}
