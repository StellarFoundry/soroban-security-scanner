//! Rule pack ecosystem: manifests, signing, and verification.
//!
//! Rule packs allow community and third-party security rules to be packaged,
//! distributed, and verified cryptographically without modifying the core scanner.

pub mod conformance;
pub mod loader;
pub mod manifest;
pub mod registry;
pub mod sandbox;
pub mod signing;

pub use conformance::{
    ConformanceError, ConformanceReport, ConformanceRunner, ConformanceSpec, ExpectedFinding,
    MAX_CONFORMANCE_SPEC_SIZE, MAX_EXPECTED_FINDINGS,
};
pub use loader::{
    validate_manifest, LoadedPack, PackLoadError, PackLoader, MAX_PACK_MANIFEST_SIZE,
    MAX_PACK_NAME_LEN, MAX_PACK_RULES, MAX_PACK_SIGNATURE_SIZE,
};
pub use manifest::{
    sha256_checksum, PackCapability, PackManifest, PackManifestError, PackMetadata,
    PackRuleMetadata, MAX_PACK_MANIFEST_BYTES, PACK_MANIFEST_SCHEMA_VERSION, SCANNER_CAPABILITIES,
};
pub use registry::{
    PackRegistry, PackRegistryEntry, PackRegistryError, PACK_REGISTRY_SCHEMA_VERSION,
};
pub use sandbox::{
    run_bounded, PackLimitError, PackLimits, PackOutcome, DEFAULT_MAX_DURATION,
    DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_RULES,
};
pub use signing::{
    DetachedSignature, KeyRing, KeyStatus, PackSigner, PackVerificationError, PackVerifier,
    TrustedKey, VerificationPolicy, VerificationResult, ALGORITHM_ED25519, MAX_VERIFY_PAYLOAD_SIZE,
};
