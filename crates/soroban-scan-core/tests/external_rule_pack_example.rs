//! Validates the example external rule pack (Issue #369).
//!
//! The example is data-only: loading it must validate exactly two rules and
//! every canonical-JSON checksum. Unsigned verification is allowed here because
//! the example ships without a production signing key.

use std::path::PathBuf;

use soroban_scan_core::pack::{
    KeyRing, PackManifest, PackVerifier, VerificationPolicy, VerificationResult,
};

fn example_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/external-rule-pack")
}

#[test]
fn example_pack_has_two_rules_with_valid_checksums() {
    let manifest =
        PackManifest::load_file(&example_dir().join("pack.toml")).expect("example pack loads");
    manifest.validate().expect("example pack validates");
    assert_eq!(manifest.pack.name, "soroban-example-rules");
    assert_eq!(manifest.rules.len(), 2);
    assert_eq!(manifest.rules[0].id, "EXPL-101");
    assert_eq!(manifest.rules[1].id, "EXPL-102");
    for rule in &manifest.rules {
        assert_eq!(rule.checksum, rule.expected_checksum());
        assert!(example_dir()
            .join("fixtures")
            .join(rule.id.to_lowercase())
            .is_dir());
    }
}

#[test]
fn example_pack_can_be_verified_as_unsigned() {
    let result = PackVerifier::verify_pack_dir(
        &example_dir(),
        &KeyRing::new(),
        VerificationPolicy::AllowUnsigned,
    );
    assert_eq!(result, Ok(VerificationResult::UnsignedAllowed));
}
