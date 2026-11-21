//! Rule pack ecosystem: manifests, signing, and verification.
//!
//! Rule packs allow community and third-party security rules to be packaged,
//! distributed, and verified cryptographically without modifying the core scanner.

pub mod conformance;
pub mod loader;
pub mod manifest;
pub mod signing;

pub use conformance::{
    ConformanceError, ConformanceReport, ConformanceRunner, ConformanceSpec, ExpectedFinding,
    MAX_CONFORMANCE_SPEC_SIZE, MAX_EXPECTED_FINDINGS,
};
pub use loader::{
    validate_manifest, LoadedPack, PackLoadError, PackLoader, MAX_PACK_MANIFEST_SIZE,
    MAX_PACK_NAME_LEN, MAX_PACK_RULES, MAX_PACK_SIGNATURE_SIZE,
};
pub use manifest::{PackManifest, PackMetadata, PackRuleMetadata};
pub use signing::{
    DetachedSignature, KeyRing, KeyStatus, PackSigner, PackVerificationError, PackVerifier,
    TrustedKey, VerificationPolicy, VerificationResult, ALGORITHM_ED25519, MAX_VERIFY_PAYLOAD_SIZE,
};
