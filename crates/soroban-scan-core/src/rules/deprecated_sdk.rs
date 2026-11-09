//! SS-015: deprecated Soroban SDK version.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::{Finding, SourceLocation};
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

/// Minimum SDK version used when the configured value is not parseable.
pub const DEFAULT_MINIMUM_VERSION: &str = "21.0.0";

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-015",
    title: "Deprecated Soroban SDK version",
    description: "The project declares a `soroban-sdk` version older than the \
configured minimum. Older major versions can miss API fixes, security patches, \
and supported runtime behavior. This is a policy signal: review the changelog \
and upgrade when practical.",
    category: Category::Dependencies,
    default_severity: Severity::Low,
    default_confidence: Confidence::Medium,
    remediation: "Upgrade `soroban-sdk` to at least the minimum configured in \
`minimum_soroban_sdk` (default 21.0.0), then rebuild and rerun the contract \
tests.",
    references: &[
        "https://github.com/stellar/rs-soroban-sdk/releases",
        "https://developers.stellar.org/docs",
    ],
};

/// Detects manifests that pin an old `soroban-sdk` version.
pub struct DeprecatedSdkVersion;

impl Rule for DeprecatedSdkVersion {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        let minimum = parse_version(ctx.minimum_soroban_sdk())
            .or_else(|| parse_version(DEFAULT_MINIMUM_VERSION))
            .unwrap_or((21, 0, 0));
        for manifest in &ctx.project().manifests {
            let Some(dependency) = manifest.dependency("soroban-sdk") else {
                continue;
            };
            let Some(declared) = dependency.version.as_deref() else {
                continue;
            };
            let Some(version) = parse_version(declared) else {
                continue;
            };
            if version >= minimum {
                continue;
            }
            let location = SourceLocation::new(ctx.relative_path(&manifest.path), 1);
            let evidence = format!(
                "soroban-sdk `{declared}` is older than the minimum supported version `{}.{}.{}`",
                minimum.0, minimum.1, minimum.2
            );
            out.push(Finding::new(&METADATA, location, evidence));
        }
    }
}

/// Parses the first numeric version in a Cargo requirement.
///
/// Handles `20`, `20.1`, `20.1.2`, `^20.1.2`, `>=20.1.2`, and similar forms.
pub(crate) fn parse_version(requirement: &str) -> Option<(u64, u64, u64)> {
    let start = requirement.find(|c: char| c.is_ascii_digit())?;
    let rest = &requirement[start..];
    let mut parts = rest.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine;
    use crate::registry::RuleRegistry;

    fn scan(manifest: &str) -> Vec<Finding> {
        let registry = RuleRegistry::with_default_rules();
        engine::scan_manifest_str("Cargo.toml", manifest, &ScanConfig::default(), &registry)
            .unwrap()
            .findings
            .into_iter()
            .filter(|finding| finding.rule_id == "SS-015")
            .collect()
    }

    #[test]
    fn flags_an_old_sdk_version_at_the_manifest() {
        let findings = scan(
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
             [dependencies]\nsoroban-sdk = \"20.5.0\"\n",
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].location.file,
            std::path::PathBuf::from("Cargo.toml")
        );
        assert_eq!(findings[0].location.line, 1);
        assert!(findings[0].evidence.contains("20.5.0"));
    }

    #[test]
    fn does_not_flag_a_supported_version() {
        let findings = scan(
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
             [dependencies]\nsoroban-sdk = \"21.7.7\"\n",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn respects_the_configured_minimum() {
        let registry = RuleRegistry::with_default_rules();
        let config = ScanConfig {
            minimum_soroban_sdk: "25.0.0".to_string(),
            ..ScanConfig::default()
        };
        let outcome = engine::scan_manifest_str(
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n\
             [dependencies]\nsoroban-sdk = \"21.7.7\"\n",
            &config,
            &registry,
        )
        .unwrap();
        assert!(outcome
            .findings
            .iter()
            .any(|finding| finding.rule_id == "SS-015"));
    }

    #[test]
    fn parses_common_requirement_forms() {
        assert_eq!(parse_version("20.5.0"), Some((20, 5, 0)));
        assert_eq!(parse_version("^21.0.0"), Some((21, 0, 0)));
        assert_eq!(parse_version(">=21.7"), Some((21, 7, 0)));
        assert_eq!(parse_version("20"), Some((20, 0, 0)));
        assert_eq!(parse_version("*"), None);
    }
}
