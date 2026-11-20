//! Detached signature verification and key management for rule packs.
//!
//! Rule packs can be distributed as directories or archives containing `pack.toml`.
//! To prevent tampering and supply-chain attacks, rule packs may be signed with
//! Ed25519 detached signatures (`pack.sig`).
//!
//! # Verification Policy
//!
//! By default (`VerificationPolicy::EnforceSigned`), unsigned packs are rejected.
//! When explicitly permitted (`VerificationPolicy::AllowUnsigned`), unsigned packs
//! are accepted with an audit notice.
//!
//! # Key Management
//!
//! A [`KeyRing`] maintains trusted public keys. Keys support rotation (marking
//! older keys as `Retired`) and revocation (`Revoked`). Signatures from revoked
//! keys are rejected immediately.

use std::collections::BTreeMap;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Maximum allowed pack file size for verification (10 MiB) to prevent DoS.
pub const MAX_VERIFY_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

/// Supported signature algorithms.
pub const ALGORITHM_ED25519: &str = "ed25519";

/// Lifecycle status of a trusted public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    /// Active key authorized to sign current and future packs.
    #[default]
    Active,
    /// Retired key: accepted for packs signed before retirement, but not for new releases.
    Retired,
    /// Revoked key: compromised or invalidated. Signatures are always rejected.
    Revoked,
}

/// A trusted signing key in the keyring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKey {
    /// Unique identifier for this key (e.g. "stellar-community-2026").
    pub key_id: String,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
    /// Lifecycle status.
    #[serde(default)]
    pub status: KeyStatus,
    /// Optional date or note when the key was created or rotated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    /// Optional revocation reason if revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
}

impl TrustedKey {
    /// Creates a new active trusted key.
    pub fn new(key_id: impl Into<String>, public_key_hex: impl Into<String>) -> Self {
        Self {
            key_id: key_id.into(),
            public_key: public_key_hex.into(),
            status: KeyStatus::Active,
            created_at: None,
            revocation_reason: None,
        }
    }

    /// Parses the public key into an Ed25519 `VerifyingKey`.
    pub fn verifying_key(&self) -> Result<VerifyingKey, PackVerificationError> {
        let bytes = hex::decode(self.public_key.trim()).map_err(|e| {
            PackVerificationError::MalformedKey(format!(
                "invalid hex in public key for '{}': {e}",
                self.key_id
            ))
        })?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            PackVerificationError::MalformedKey(format!(
                "public key for '{}' must be 32 bytes, got {}",
                self.key_id,
                bytes.len()
            ))
        })?;
        VerifyingKey::from_bytes(&array).map_err(|e| {
            PackVerificationError::MalformedKey(format!(
                "invalid Ed25519 public key for '{}': {e}",
                self.key_id
            ))
        })
    }
}

/// A detached signature for a rule pack payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedSignature {
    /// Signature format version.
    #[serde(default = "default_signature_version")]
    pub version: u32,
    /// Signature algorithm (e.g. "ed25519").
    pub algorithm: String,
    /// Identifier of the key that signed the pack.
    pub key_id: String,
    /// Hex-encoded 64-byte detached signature.
    pub signature: String,
}

fn default_signature_version() -> u32 {
    1
}

impl DetachedSignature {
    /// Creates a new detached signature structure.
    pub fn new(key_id: impl Into<String>, signature_hex: impl Into<String>) -> Self {
        Self {
            version: 1,
            algorithm: ALGORITHM_ED25519.to_string(),
            key_id: key_id.into(),
            signature: signature_hex.into(),
        }
    }

    /// Serializes the signature to TOML format.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Parses a detached signature from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Decodes the 64-byte Ed25519 signature.
    pub fn to_signature_bytes(&self) -> Result<[u8; 64], PackVerificationError> {
        let bytes = hex::decode(self.signature.trim()).map_err(|e| {
            PackVerificationError::MalformedSignature(format!("invalid signature hex: {e}"))
        })?;
        bytes.as_slice().try_into().map_err(|_| {
            PackVerificationError::MalformedSignature(format!(
                "signature must be 64 bytes, got {}",
                bytes.len()
            ))
        })
    }
}

/// Collection of trusted public keys for verifying rule packs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRing {
    keys: BTreeMap<String, TrustedKey>,
}

impl KeyRing {
    /// Creates an empty keyring.
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Adds or replaces a trusted key.
    pub fn add_key(&mut self, key: TrustedKey) {
        self.keys.insert(key.key_id.clone(), key);
    }

    /// Rotates an existing key: marks old key as Retired and registers new key as Active.
    pub fn rotate_key(
        &mut self,
        old_key_id: &str,
        new_key: TrustedKey,
    ) -> Result<(), PackVerificationError> {
        if let Some(old) = self.keys.get_mut(old_key_id) {
            old.status = KeyStatus::Retired;
        } else {
            return Err(PackVerificationError::UnknownKey(old_key_id.to_string()));
        }
        self.add_key(new_key);
        Ok(())
    }

    /// Revokes a key by ID with a documented reason.
    pub fn revoke_key(
        &mut self,
        key_id: &str,
        reason: impl Into<String>,
    ) -> Result<(), PackVerificationError> {
        if let Some(key) = self.keys.get_mut(key_id) {
            key.status = KeyStatus::Revoked;
            key.revocation_reason = Some(reason.into());
            Ok(())
        } else {
            Err(PackVerificationError::UnknownKey(key_id.to_string()))
        }
    }

    /// Looks up a key by ID.
    pub fn get_key(&self, key_id: &str) -> Option<&TrustedKey> {
        self.keys.get(key_id)
    }

    /// Returns the number of keys in the keyring.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true if the keyring contains no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Policy for verifying rule packs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationPolicy {
    /// Require a valid signature from a trusted key (default, fail closed).
    #[default]
    EnforceSigned,
    /// Allow unsigned packs, emitting an audit notice.
    AllowUnsigned,
}

/// The result of a successful pack verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationResult {
    /// The pack was verified with a valid signature from a trusted active or retired key.
    Verified { key_id: String, status: KeyStatus },
    /// The pack was unsigned but permitted under `VerificationPolicy::AllowUnsigned`.
    UnsignedAllowed,
}

/// Errors raised during pack signature verification.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PackVerificationError {
    #[error("unsigned pack rejected: signing is required by policy")]
    UnsignedPack,

    #[error("pack payload exceeds size limit of {0} bytes")]
    PayloadTooLarge(usize),

    #[error("unsupported signature algorithm: '{0}' (expected 'ed25519')")]
    UnsupportedAlgorithm(String),

    #[error("signing key '{0}' is not trusted in keyring")]
    UnknownKey(String),

    #[error("signing key '{key_id}' was revoked: {reason}")]
    RevokedKey { key_id: String, reason: String },

    #[error("malformed public key: {0}")]
    MalformedKey(String),

    #[error("malformed signature: {0}")]
    MalformedSignature(String),

    #[error("tampered pack: signature verification failed for key '{0}'")]
    SignatureMismatch(String),

    #[error("io error reading pack: {0}")]
    Io(String),
}

/// Helper to sign pack payloads using Ed25519.
pub struct PackSigner;

impl PackSigner {
    /// Signs a payload using an Ed25519 signing key, returning a detached signature.
    pub fn sign(key_id: &str, signing_key: &SigningKey, payload: &[u8]) -> DetachedSignature {
        let signature = signing_key.sign(payload);
        DetachedSignature::new(key_id, hex::encode(signature.to_bytes()))
    }
}

/// Verifies rule packs against detached signatures and trusted keyrings.
pub struct PackVerifier;

impl PackVerifier {
    /// Verifies raw payload bytes against an optional detached signature.
    pub fn verify(
        payload: &[u8],
        signature: Option<&DetachedSignature>,
        keyring: &KeyRing,
        policy: VerificationPolicy,
    ) -> Result<VerificationResult, PackVerificationError> {
        if payload.len() > MAX_VERIFY_PAYLOAD_SIZE {
            return Err(PackVerificationError::PayloadTooLarge(
                MAX_VERIFY_PAYLOAD_SIZE,
            ));
        }

        let Some(sig) = signature else {
            return match policy {
                VerificationPolicy::EnforceSigned => Err(PackVerificationError::UnsignedPack),
                VerificationPolicy::AllowUnsigned => Ok(VerificationResult::UnsignedAllowed),
            };
        };

        if !sig.algorithm.eq_ignore_ascii_case(ALGORITHM_ED25519) {
            return Err(PackVerificationError::UnsupportedAlgorithm(
                sig.algorithm.clone(),
            ));
        }

        let key = keyring
            .get_key(&sig.key_id)
            .ok_or_else(|| PackVerificationError::UnknownKey(sig.key_id.clone()))?;

        if key.status == KeyStatus::Revoked {
            return Err(PackVerificationError::RevokedKey {
                key_id: key.key_id.clone(),
                reason: key
                    .revocation_reason
                    .clone()
                    .unwrap_or_else(|| "key was revoked".to_string()),
            });
        }

        let verifying_key = key.verifying_key()?;
        let sig_bytes = sig.to_signature_bytes()?;
        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(payload, &signature)
            .map_err(|_| PackVerificationError::SignatureMismatch(sig.key_id.clone()))?;

        Ok(VerificationResult::Verified {
            key_id: key.key_id.clone(),
            status: key.status,
        })
    }

    /// Verifies a pack directory containing `pack.toml` and optional `pack.sig`.
    pub fn verify_pack_dir(
        dir: &Path,
        keyring: &KeyRing,
        policy: VerificationPolicy,
    ) -> Result<VerificationResult, PackVerificationError> {
        let manifest_path = dir.join("pack.toml");
        let payload = std::fs::read(&manifest_path).map_err(|e| {
            PackVerificationError::Io(format!(
                "missing or unreadable pack.toml at {}: {e}",
                manifest_path.display()
            ))
        })?;

        let sig_path = dir.join("pack.sig");
        let detached_sig = if sig_path.exists() {
            let sig_text = std::fs::read_to_string(&sig_path).map_err(|e| {
                PackVerificationError::Io(format!("cannot read {}: {e}", sig_path.display()))
            })?;
            Some(DetachedSignature::from_toml(&sig_text).map_err(|e| {
                PackVerificationError::MalformedSignature(format!(
                    "invalid TOML in {}: {e}",
                    sig_path.display()
                ))
            })?)
        } else {
            None
        };

        Self::verify(&payload, detached_sig.as_ref(), keyring, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair(seed_byte: u8) -> (SigningKey, String, String) {
        let seed = [seed_byte; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let pub_hex = hex::encode(verifying_key.to_bytes());
        let key_id = format!("test-key-{seed_byte}");
        (signing_key, key_id, pub_hex)
    }

    #[test]
    fn valid_signature_verifies() {
        let (sk, key_id, pub_hex) = test_keypair(1);
        let mut keyring = KeyRing::new();
        keyring.add_key(TrustedKey::new(&key_id, &pub_hex));

        let payload = b"{\"pack\": {\"name\": \"test-pack\", \"version\": \"1.0.0\"}}";
        let sig = PackSigner::sign(&key_id, &sk, payload);

        let result = PackVerifier::verify(
            payload,
            Some(&sig),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(
            result,
            Ok(VerificationResult::Verified {
                key_id: key_id.clone(),
                status: KeyStatus::Active,
            })
        );
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let (sk, key_id, pub_hex) = test_keypair(2);
        let mut keyring = KeyRing::new();
        keyring.add_key(TrustedKey::new(&key_id, &pub_hex));

        let payload = b"original pack content";
        let sig = PackSigner::sign(&key_id, &sk, payload);

        let tampered = b"tampered pack content";
        let result = PackVerifier::verify(
            tampered,
            Some(&sig),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(
            result,
            Err(PackVerificationError::SignatureMismatch(key_id))
        );
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (sk, key_id, pub_hex) = test_keypair(3);
        let mut keyring = KeyRing::new();
        keyring.add_key(TrustedKey::new(&key_id, &pub_hex));

        let payload = b"pack content";
        let mut sig = PackSigner::sign(&key_id, &sk, payload);

        let mut sig_chars: Vec<char> = sig.signature.chars().collect();
        sig_chars[0] = if sig_chars[0] == '0' { '1' } else { '0' };
        sig.signature = sig_chars.into_iter().collect();

        let result = PackVerifier::verify(
            payload,
            Some(&sig),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(
            result,
            Err(PackVerificationError::SignatureMismatch(key_id))
        );
    }

    #[test]
    fn unsigned_pack_is_rejected_under_enforce_signed() {
        let keyring = KeyRing::new();
        let payload = b"unsigned pack content";

        let result =
            PackVerifier::verify(payload, None, &keyring, VerificationPolicy::EnforceSigned);
        assert_eq!(result, Err(PackVerificationError::UnsignedPack));
    }

    #[test]
    fn unsigned_pack_is_allowed_under_allow_unsigned() {
        let keyring = KeyRing::new();
        let payload = b"unsigned pack content";

        let result =
            PackVerifier::verify(payload, None, &keyring, VerificationPolicy::AllowUnsigned);
        assert_eq!(result, Ok(VerificationResult::UnsignedAllowed));
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let (sk, key_id, _pub_hex) = test_keypair(4);
        let keyring = KeyRing::new();

        let payload = b"pack content";
        let sig = PackSigner::sign(&key_id, &sk, payload);

        let result = PackVerifier::verify(
            payload,
            Some(&sig),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(result, Err(PackVerificationError::UnknownKey(key_id)));
    }

    #[test]
    fn revoked_key_is_rejected() {
        let (sk, key_id, pub_hex) = test_keypair(5);
        let mut keyring = KeyRing::new();
        let mut key = TrustedKey::new(&key_id, &pub_hex);
        key.status = KeyStatus::Revoked;
        key.revocation_reason = Some("Key compromised on 2026-11-20".to_string());
        keyring.add_key(key);

        let payload = b"pack content";
        let sig = PackSigner::sign(&key_id, &sk, payload);

        let result = PackVerifier::verify(
            payload,
            Some(&sig),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(
            result,
            Err(PackVerificationError::RevokedKey {
                key_id,
                reason: "Key compromised on 2026-11-20".to_string(),
            })
        );
    }

    #[test]
    fn key_rotation_preserves_verification_of_retired_keys() {
        let (sk1, key_id_1, pub_hex_1) = test_keypair(6);
        let (sk2, key_id_2, pub_hex_2) = test_keypair(7);

        let mut keyring = KeyRing::new();
        keyring.add_key(TrustedKey::new(&key_id_1, &pub_hex_1));

        let payload1 = b"pack 1 content";
        let sig1 = PackSigner::sign(&key_id_1, &sk1, payload1);

        let new_key = TrustedKey::new(&key_id_2, &pub_hex_2);
        keyring.rotate_key(&key_id_1, new_key).unwrap();

        let res1 = PackVerifier::verify(
            payload1,
            Some(&sig1),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(
            res1,
            Ok(VerificationResult::Verified {
                key_id: key_id_1,
                status: KeyStatus::Retired,
            })
        );

        let payload2 = b"pack 2 content";
        let sig2 = PackSigner::sign(&key_id_2, &sk2, payload2);

        let res2 = PackVerifier::verify(
            payload2,
            Some(&sig2),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(
            res2,
            Ok(VerificationResult::Verified {
                key_id: key_id_2,
                status: KeyStatus::Active,
            })
        );
    }

    #[test]
    fn payload_too_large_is_rejected() {
        let keyring = KeyRing::new();
        let payload = vec![0u8; MAX_VERIFY_PAYLOAD_SIZE + 1];

        let result =
            PackVerifier::verify(&payload, None, &keyring, VerificationPolicy::AllowUnsigned);
        assert_eq!(
            result,
            Err(PackVerificationError::PayloadTooLarge(
                MAX_VERIFY_PAYLOAD_SIZE
            ))
        );
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let (_sk, key_id, pub_hex) = test_keypair(8);
        let mut keyring = KeyRing::new();
        keyring.add_key(TrustedKey::new(&key_id, &pub_hex));

        let mut sig = DetachedSignature::new(&key_id, "aa".repeat(64));
        sig.algorithm = "rsa4096".to_string();

        let payload = b"pack content";
        let result = PackVerifier::verify(
            payload,
            Some(&sig),
            &keyring,
            VerificationPolicy::EnforceSigned,
        );
        assert_eq!(
            result,
            Err(PackVerificationError::UnsupportedAlgorithm(
                "rsa4096".to_string()
            ))
        );
    }
}
