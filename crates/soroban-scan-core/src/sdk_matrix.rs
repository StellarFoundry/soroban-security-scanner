//! Soroban SDK version support matrix.
//!
//! Rule behaviour can differ between SDK releases, so support is bounded and
//! explicit. The matrix below lists the releases the rule suite is verified
//! against in CI. A declared `soroban-sdk` requirement outside the supported
//! range emits `SDK-001`; the scanner still runs, but coverage may be
//! inaccurate. The scanner never builds or downloads an SDK.

use std::collections::BTreeSet;

use crate::model::{Diagnostic, DiagnosticCode, Manifest};

/// Oldest `soroban-sdk` release the rule suite is verified against.
pub const MIN_SUPPORTED: (u64, u64, u64) = (20, 5, 0);

/// First release after the supported range (exclusive).
pub const MAX_SUPPORTED_EXCLUSIVE: (u64, u64, u64) = (30, 0, 0);

/// Versions pinned by fixtures and exercised by the CI matrix.
pub const MATRIX: &[(&str, &str)] = &[
    ("20.5.0", "fixtures/sdk-matrix/soroban-sdk-20"),
    ("21.7.7", "fixtures/sdk-matrix/soroban-sdk-21"),
    ("29.0.1", "fixtures/sdk-matrix/soroban-sdk-29"),
];

/// Parses the first numeric version in a Cargo requirement.
///
/// Handles `20.5.0`, `20`, `^20.5`, `>=20.5, <21`, and similar forms. Returns
/// `None` when no numeric version is present, so the caller never guesses.
pub fn parse_requirement(requirement: &str) -> Option<(u64, u64, u64)> {
    let start = requirement.find(|c: char| c.is_ascii_digit())?;
    let rest = &requirement[start..];
    let mut parts = rest.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

/// Returns true when a parsed version is inside the supported range.
pub fn is_supported(version: (u64, u64, u64)) -> bool {
    version >= MIN_SUPPORTED && version < MAX_SUPPORTED_EXCLUSIVE
}

/// Returns one warning per distinct unsupported `soroban-sdk` version.
///
/// Requirements without a numeric version are left alone rather than guessed
/// at. Identical versions across manifests are aggregated into one diagnostic.
pub fn diagnostics(manifests: &[Manifest]) -> Vec<Diagnostic> {
    let mut unsupported = BTreeSet::new();
    for manifest in manifests {
        let Some(dependency) = manifest.dependency("soroban-sdk") else {
            continue;
        };
        let Some(requirement) = dependency.version.as_deref() else {
            continue;
        };
        let Some(version) = parse_requirement(requirement) else {
            continue;
        };
        if !is_supported(version) {
            unsupported.insert(requirement.to_string());
        }
    }

    let verified = MATRIX
        .iter()
        .map(|(version, _)| *version)
        .collect::<Vec<_>>()
        .join(", ");
    unsupported
        .into_iter()
        .map(|requirement| {
            Diagnostic::warning(
                DiagnosticCode::UnsupportedSdkVersion,
                format!(
                    "soroban-sdk `{requirement}` is outside the supported matrix \
                     (>={}.{}.{}, <{}.{}.{}); rule coverage may be inaccurate. \
                     Verified versions: {verified}",
                    MIN_SUPPORTED.0,
                    MIN_SUPPORTED.1,
                    MIN_SUPPORTED.2,
                    MAX_SUPPORTED_EXCLUSIVE.0,
                    MAX_SUPPORTED_EXCLUSIVE.1,
                    MAX_SUPPORTED_EXCLUSIVE.2,
                ),
                None,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::parse_manifest;
    use std::path::Path;

    fn manifest(toml: &str) -> Manifest {
        parse_manifest(Path::new("Cargo.toml"), toml).unwrap()
    }

    #[test]
    fn parses_common_requirements() {
        assert_eq!(parse_requirement("20.5.0"), Some((20, 5, 0)));
        assert_eq!(parse_requirement("^21.7.7"), Some((21, 7, 7)));
        assert_eq!(parse_requirement(">=20.5, <21"), Some((20, 5, 0)));
        assert_eq!(parse_requirement("29"), Some((29, 0, 0)));
        assert_eq!(parse_requirement("*"), None);
    }

    #[test]
    fn bounds_are_inclusive_minimum_and_exclusive_maximum() {
        assert!(!is_supported((20, 4, 0)));
        assert!(is_supported(MIN_SUPPORTED));
        assert!(is_supported((29, 0, 1)));
        assert!(!is_supported(MAX_SUPPORTED_EXCLUSIVE));
    }

    #[test]
    fn aggregates_unsupported_versions_and_ignores_supported_ones() {
        let manifests = vec![
            manifest("[dependencies]\nsoroban-sdk = \"19.0.0\"\n"),
            manifest("[dependencies]\nsoroban-sdk = \"19.0.0\"\n"),
            manifest("[dependencies]\nsoroban-sdk = \"21.7.7\"\n"),
            manifest("[dependencies]\nsoroban-sdk = \"*\"\n"),
        ];
        let diagnostics = diagnostics(&manifests);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, DiagnosticCode::UnsupportedSdkVersion);
        assert!(diagnostics[0].message.contains("19.0.0"));
        assert!(diagnostics[0].message.contains("Verified versions"));
    }
}
