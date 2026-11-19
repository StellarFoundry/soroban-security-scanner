//! Static WASM target analysis (#382).
//!
//! The scanner reads declared targets but never builds or executes Cargo.

use std::path::PathBuf;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::engine;
use soroban_scan_core::model::{DiagnosticCode, ProjectKind};
use soroban_scan_core::project;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/targets")
        .join(name)
}

fn with_targets() -> DiscoveryOptions {
    DiscoveryOptions {
        target_analysis: true,
        ..DiscoveryOptions::default()
    }
}

#[test]
fn target_analysis_is_opt_in() {
    let loaded = project::load(&fixture("wasm32"), &DiscoveryOptions::default()).unwrap();
    assert!(loaded.project.target.is_none());
    let soroban_deps = loaded
        .project
        .manifests
        .iter()
        .flat_map(|manifest| &manifest.dependencies)
        .filter(|dependency| dependency.name == "soroban-sdk")
        .count();
    assert_eq!(soroban_deps, 2, "both target tables are kept by default");
}

#[test]
fn wasm32_target_is_detected_and_host_dependencies_are_filtered() {
    let loaded = project::load(&fixture("wasm32"), &with_targets()).unwrap();
    let target = loaded.project.target.as_ref().expect("target info");

    assert_eq!(target.requested.as_deref(), Some("wasm32-unknown-unknown"));
    assert!(target.wasm32);
    assert!(target.supported);
    assert!(target.crate_types.contains(&"cdylib".to_string()));
    assert!(!target.evidence.is_empty());
    assert!(target
        .evidence
        .iter()
        .all(|evidence| !evidence.contains(env!("CARGO_MANIFEST_DIR"))));

    assert!(loaded.project.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::TargetDetected
            && diagnostic.level == soroban_scan_core::model::DiagnosticLevel::Info
    }));

    let versions: Vec<_> = loaded
        .project
        .manifests
        .iter()
        .flat_map(|manifest| &manifest.dependencies)
        .filter(|dependency| dependency.name == "soroban-sdk")
        .filter_map(|dependency| dependency.version.as_deref())
        .collect();
    assert_eq!(versions, vec!["21.0.0"], "host-only dependency is filtered");
    assert_eq!(loaded.project.kind, ProjectKind::LikelySoroban);
}

#[test]
fn unsupported_target_is_reported_and_does_not_guess() {
    let loaded = project::load(&fixture("unsupported"), &with_targets()).unwrap();
    let target = loaded.project.target.as_ref().expect("target info");

    assert_eq!(
        target.requested.as_deref(),
        Some("x86_64-unknown-linux-gnu")
    );
    assert!(!target.wasm32);
    assert!(!target.supported);
    assert!(loaded.project.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::TargetUnsupported
            && diagnostic.message.contains("unsupported target analysis")
    }));

    assert!(
        loaded
            .project
            .manifests
            .iter()
            .flat_map(|manifest| &manifest.dependencies)
            .all(|dependency| dependency.name != "soroban-sdk"),
        "wasm-scoped dependency must not leak into a non-wasm target"
    );
    assert_eq!(loaded.project.kind, ProjectKind::GenericRust);
}

#[test]
fn missing_target_configuration_is_reported_without_guessing() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/projects/generic-rust");
    let loaded = project::load(&root, &with_targets()).unwrap();
    let target = loaded.project.target.as_ref().expect("target info");
    assert_eq!(target.requested, None);
    assert!(!target.wasm32);
    assert!(target.supported);
    assert!(
        !loaded.project.diagnostics.iter().any(|diagnostic| matches!(
            diagnostic.code,
            DiagnosticCode::TargetDetected
                | DiagnosticCode::TargetUnsupported
                | DiagnosticCode::TargetConfigUnreadable
        ))
    );
}

#[test]
fn target_info_is_exposed_in_json_stats() {
    let config = ScanConfig {
        target_analysis: true,
        ..ScanConfig::default()
    };
    let outcome = engine::run_scan(
        &fixture("wasm32"),
        &config,
        &RuleRegistry::with_default_rules(),
    )
    .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&report::render_json(&outcome).unwrap()).unwrap();
    assert_eq!(
        json["stats"]["target"]["requested"],
        "wasm32-unknown-unknown"
    );
    assert_eq!(json["stats"]["target"]["wasm32"], true);
    assert_eq!(json["stats"]["target"]["supported"], true);
}
