//! Validates the rule pack template (Issue #367).
//!
//! The template is data-only: loading it must validate the starter rules and
//! every canonical-JSON checksum. Unsigned verification is allowed because
//! the template ships without a production signing key.

use std::path::PathBuf;

use soroban_scan_core::pack::{
    KeyRing, PackManifest, PackVerifier, VerificationPolicy, VerificationResult,
};

fn template_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/rule-pack-template")
}

#[test]
fn template_pack_has_starter_rules_with_valid_checksums() {
    let manifest =
        PackManifest::load_file(&template_dir().join("pack.toml")).expect("template pack loads");
    manifest.validate().expect("template pack validates");
    assert_eq!(manifest.pack.name, "soroban-starter-pack");
    assert_eq!(manifest.rules.len(), 2);
    assert_eq!(manifest.rules[0].id, "TMPL-001");
    assert_eq!(manifest.rules[1].id, "TMPL-002");
    for rule in &manifest.rules {
        assert_eq!(rule.checksum, rule.expected_checksum());
        let fixture_dir = template_dir().join("fixtures").join(rule.id.to_lowercase());
        assert!(fixture_dir.is_dir(), "fixture dir exists for {}", rule.id);
        assert!(
            fixture_dir.join("positive.rs").is_file(),
            "positive fixture exists for {}",
            rule.id
        );
        assert!(
            fixture_dir.join("negative.rs").is_file(),
            "negative fixture exists for {}",
            rule.id
        );
    }
}

#[test]
fn template_pack_can_be_verified_as_unsigned() {
    let result = PackVerifier::verify_pack_dir(
        &template_dir(),
        &KeyRing::new(),
        VerificationPolicy::AllowUnsigned,
    );
    assert_eq!(result, Ok(VerificationResult::UnsignedAllowed));
}
