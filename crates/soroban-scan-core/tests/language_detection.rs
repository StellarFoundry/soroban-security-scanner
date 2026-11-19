//! Language detection evidence (#384).
//!
//! Only Rust is recognized today. Incomplete evidence is marked weak instead of
//! being guessed at.

use std::path::PathBuf;

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::engine;
use soroban_scan_core::model::DetectionConfidence;
use soroban_scan_core::project;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/detection")
        .join(name)
}

fn load(name: &str) -> soroban_scan_core::project::LoadedProject {
    project::load(&fixture(name), &DiscoveryOptions::default()).unwrap()
}

#[test]
fn rust_project_records_manifest_and_source_evidence() {
    let loaded = load("rust");
    let detection = &loaded.project.detection;
    assert_eq!(detection.frontend, "rust");
    assert_eq!(detection.language, "rust");
    assert_eq!(detection.project_type, "generic_rust");
    assert_eq!(detection.confidence, DetectionConfidence::Strong);
    assert!(detection
        .evidence
        .iter()
        .any(|item| item.kind == "manifest"));
    assert!(detection.evidence.iter().any(|item| item.kind == "source"));
    assert!(detection.evidence.iter().all(|item| item
        .path
        .as_deref()
        .is_none_or(|path| !path.contains(env!("CARGO_MANIFEST_DIR")))));
}

#[test]
fn soroban_project_records_dependency_and_macro_evidence() {
    let loaded = load("rust-soroban");
    let detection = &loaded.project.detection;
    assert_eq!(detection.project_type, "confirmed_soroban");
    assert_eq!(detection.confidence, DetectionConfidence::Strong);
    assert!(detection
        .evidence
        .iter()
        .any(|item| item.kind == "dependency"));
    assert!(detection
        .evidence
        .iter()
        .any(|item| item.kind == "contract-macro"));
}

#[test]
fn missing_manifest_is_marked_weak_not_guessed() {
    let loaded = load("rust-weak");
    let detection = &loaded.project.detection;
    assert_eq!(detection.language, "rust");
    assert_eq!(detection.confidence, DetectionConfidence::Weak);
    assert!(detection.evidence.iter().any(|item| item.kind == "source"));
    assert!(!detection
        .evidence
        .iter()
        .any(|item| item.kind == "manifest"));
}

#[test]
fn no_evidence_is_reported_as_unknown_weak() {
    let loaded = load("unknown");
    let detection = &loaded.project.detection;
    assert_eq!(detection.frontend, "unknown");
    assert_eq!(detection.language, "unknown");
    assert_eq!(detection.project_type, "unknown");
    assert_eq!(detection.confidence, DetectionConfidence::Weak);
    assert!(detection.evidence.is_empty());
}

#[test]
fn detection_is_exposed_in_json_stats() {
    let outcome = engine::run_scan(
        &fixture("rust-soroban"),
        &ScanConfig::default(),
        &RuleRegistry::with_default_rules(),
    )
    .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&report::render_json(&outcome).unwrap()).unwrap();
    assert_eq!(json["stats"]["detection"]["language"], "rust");
    assert_eq!(
        json["stats"]["detection"]["project_type"],
        "confirmed_soroban"
    );
    assert_eq!(json["stats"]["detection"]["confidence"], "strong");
    assert!(json["stats"]["detection"]["evidence"].is_array());
}
