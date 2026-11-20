//! Rule pack signing and verification integration tests (Issue #362).

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use soroban_scan_core::pack::{
    DetachedSignature, KeyRing, KeyStatus, PackSigner, PackVerificationError, PackVerifier,
    TrustedKey, VerificationPolicy, VerificationResult,
};

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/rule-packs")
}

fn deterministic_keypair(seed_byte: u8, key_id: &str) -> (SigningKey, TrustedKey) {
    let seed = [seed_byte; 32];
    let sk = SigningKey::from_bytes(&seed);
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());
    let trusted = TrustedKey::new(key_id, pk_hex);
    (sk, trusted)
}

fn setup_test_keyring() -> (KeyRing, SigningKey, SigningKey, SigningKey) {
    let mut keyring = KeyRing::new();

    // 1. Active trusted key
    let (sk_active, key_active) = deterministic_keypair(10, "stellar-foundry-active");
    keyring.add_key(key_active);

    // 2. Retired key (rotated)
    let (sk_retired, mut key_retired) = deterministic_keypair(11, "stellar-foundry-retired");
    key_retired.status = KeyStatus::Retired;
    key_retired.created_at = Some("2025-01-01".to_string());
    keyring.add_key(key_retired);

    // 3. Revoked key
    let (_sk_revoked, mut key_revoked) = deterministic_keypair(12, "compromised-key-2026");
    key_revoked.status = KeyStatus::Revoked;
    key_revoked.revocation_reason = Some("Key leaked in public CI log on 2026-05-01".to_string());
    keyring.add_key(key_revoked);

    // 4. Untrusted key (not in keyring)
    let (sk_untrusted, _) = deterministic_keypair(13, "untrusted-author-key");

    (keyring, sk_active, sk_retired, sk_untrusted)
}

fn write_pack_fixture(dir: &Path, manifest_content: &str, sig: Option<&DetachedSignature>) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("pack.toml"), manifest_content).unwrap();
    if let Some(s) = sig {
        std::fs::write(dir.join("pack.sig"), s.to_toml().unwrap()).unwrap();
    } else {
        let _ = std::fs::remove_file(dir.join("pack.sig"));
    }
}

#[test]
fn generate_and_verify_all_rule_pack_fixtures() {
    let (keyring, sk_active, _sk_retired, sk_untrusted) = setup_test_keyring();
    let root = fixtures_root();
    std::fs::create_dir_all(&root).unwrap();

    let valid_manifest = r#"[pack]
name = "soroban-defi-rules"
version = "0.1.0"
description = "Community rules for common Soroban DeFi attack vectors"
authors = ["Stellar Foundry <security@stellarfoundry.org>"]
min_scanner_version = "0.2.0"

[[rules]]
id = "COMM-001"
title = "Unbounded slippage in swap invocation"
category = "defi"
default_severity = "high"
default_confidence = "medium"
description = "Flags swap calls where max_slippage is unconstrained or zero."
"#;

    // 1. Valid signed pack
    let valid_dir = root.join("valid-signed");
    let sig_valid = PackSigner::sign(
        "stellar-foundry-active",
        &sk_active,
        valid_manifest.as_bytes(),
    );
    write_pack_fixture(&valid_dir, valid_manifest, Some(&sig_valid));

    let res =
        PackVerifier::verify_pack_dir(&valid_dir, &keyring, VerificationPolicy::EnforceSigned);
    assert_eq!(
        res,
        Ok(VerificationResult::Verified {
            key_id: "stellar-foundry-active".to_string(),
            status: KeyStatus::Active,
        })
    );

    // 2. Tampered pack
    let tampered_dir = root.join("tampered");
    let tampered_manifest = r#"[pack]
name = "soroban-defi-rules"
version = "0.1.0"
description = "MODIFIED / TAMPERED MANIFEST"
authors = ["Attacker <malicious@example.com>"]
"#;
    // Keep signature from valid manifest, but write modified manifest content
    write_pack_fixture(&tampered_dir, tampered_manifest, Some(&sig_valid));

    let res =
        PackVerifier::verify_pack_dir(&tampered_dir, &keyring, VerificationPolicy::EnforceSigned);
    assert_eq!(
        res,
        Err(PackVerificationError::SignatureMismatch(
            "stellar-foundry-active".to_string()
        ))
    );

    // 3. Unsigned pack
    let unsigned_dir = root.join("unsigned");
    write_pack_fixture(&unsigned_dir, valid_manifest, None);

    // Reject under EnforceSigned
    let res =
        PackVerifier::verify_pack_dir(&unsigned_dir, &keyring, VerificationPolicy::EnforceSigned);
    assert_eq!(res, Err(PackVerificationError::UnsignedPack));

    // Allow under AllowUnsigned
    let res =
        PackVerifier::verify_pack_dir(&unsigned_dir, &keyring, VerificationPolicy::AllowUnsigned);
    assert_eq!(res, Ok(VerificationResult::UnsignedAllowed));

    // 4. Revoked key pack
    let (sk_revoked, _) = deterministic_keypair(12, "compromised-key-2026");
    let revoked_dir = root.join("revoked-key");
    let sig_revoked = PackSigner::sign(
        "compromised-key-2026",
        &sk_revoked,
        valid_manifest.as_bytes(),
    );
    write_pack_fixture(&revoked_dir, valid_manifest, Some(&sig_revoked));

    let res =
        PackVerifier::verify_pack_dir(&revoked_dir, &keyring, VerificationPolicy::EnforceSigned);
    assert_eq!(
        res,
        Err(PackVerificationError::RevokedKey {
            key_id: "compromised-key-2026".to_string(),
            reason: "Key leaked in public CI log on 2026-05-01".to_string(),
        })
    );

    // 5. Untrusted key pack
    let untrusted_dir = root.join("untrusted-key");
    let sig_untrusted = PackSigner::sign(
        "untrusted-author-key",
        &sk_untrusted,
        valid_manifest.as_bytes(),
    );
    write_pack_fixture(&untrusted_dir, valid_manifest, Some(&sig_untrusted));

    let res =
        PackVerifier::verify_pack_dir(&untrusted_dir, &keyring, VerificationPolicy::EnforceSigned);
    assert_eq!(
        res,
        Err(PackVerificationError::UnknownKey(
            "untrusted-author-key".to_string()
        ))
    );
}
