//! Soroban SDK version matrix (#383).
//!
//! The rule suite must behave consistently across the verified SDK releases,
//! and a declared version outside the matrix must warn instead of claiming
//! support. CI runs this target once per matrix version by setting
//! `SOROBAN_SDK_MATRIX`; without it, every supported fixture runs locally.

use std::path::PathBuf;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::engine;
use soroban_scan_core::model::{DiagnosticCode, DiagnosticLevel, ProjectKind};
use soroban_scan_core::project;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::sdk_matrix;

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative)
}

fn selected_version() -> Option<String> {
    std::env::var("SOROBAN_SDK_MATRIX").ok()
}

#[test]
fn supported_matrix_runs_the_rule_suite() {
    let selected = selected_version();
    let registry = RuleRegistry::with_default_rules();
    let mut ran = 0usize;

    for (version, relative) in sdk_matrix::MATRIX {
        if selected
            .as_deref()
            .is_some_and(|selected| selected != *version)
        {
            continue;
        }
        ran += 1;

        let outcome = engine::run_scan(&fixture(relative), &ScanConfig::default(), &registry)
            .unwrap_or_else(|error| {
                panic!("soroban-sdk {version} fixture failed to scan: {error}")
            });

        assert_eq!(
            outcome.project.kind,
            ProjectKind::ConfirmedSoroban,
            "soroban-sdk {version} must classify as a confirmed contract"
        );
        assert!(
            outcome
                .project
                .soroban
                .sdk_versions
                .iter()
                .any(|detected| detected == version),
            "expected soroban-sdk {version} in {:?}",
            outcome.project.soroban.sdk_versions
        );
        assert!(
            !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == DiagnosticCode::UnsupportedSdkVersion }),
            "supported version {version} must not warn"
        );

        let rules: Vec<&str> = outcome
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        for required in ["SS-001", "SS-008"] {
            assert!(
                rules.contains(&required),
                "soroban-sdk {version} did not report {required}; findings: {rules:?}"
            );
        }
        assert!(
            !outcome
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == DiagnosticCode::RulePanicked),
            "a rule panicked on soroban-sdk {version}"
        );
    }

    assert!(
        ran > 0,
        "SOROBAN_SDK_MATRIX={:?} did not match any supported fixture",
        selected
    );
}

#[test]
fn unsupported_sdk_versions_warn() {
    for (relative, version) in [
        ("fixtures/sdk-matrix/soroban-sdk-19", "19.0.0"),
        ("fixtures/sdk-matrix/soroban-sdk-30", "30.0.0"),
    ] {
        let loaded = project::load(&fixture(relative), &DiscoveryOptions::default())
            .expect("fixture must load");
        let warning = loaded
            .project
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == DiagnosticCode::UnsupportedSdkVersion)
            .unwrap_or_else(|| panic!("soroban-sdk {version} did not warn"));
        assert_eq!(warning.level, DiagnosticLevel::Warning);
        assert!(warning.message.contains(version));
        assert!(warning.message.contains("outside the supported matrix"));
    }
}

#[test]
fn the_verified_matrix_is_not_empty() {
    assert!(!sdk_matrix::MATRIX.is_empty());
}
