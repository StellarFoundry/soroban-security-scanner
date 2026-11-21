//! Rule pack ecosystem: manifests, signing, and verification.
//!
//! Rule packs allow community and third-party security rules to be packaged,
//! distributed, and verified cryptographically without modifying the core scanner.

pub mod manifest;
pub mod signing;

pub use manifest::{
    PackCapability, PackManifest, PackManifestError, PackMetadata, PackRuleMetadata,
    MAX_PACK_MANIFEST_BYTES, PACK_MANIFEST_SCHEMA_VERSION,
};
pub use signing::{
    DetachedSignature, KeyRing, KeyStatus, PackSigner, PackVerificationError, PackVerifier,
    TrustedKey, VerificationPolicy, VerificationResult, ALGORITHM_ED25519, MAX_VERIFY_PAYLOAD_SIZE,
};
