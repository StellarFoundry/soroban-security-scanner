//! Workspace-inherited dependency versions (#43).
//!
//! A member declaring `soroban-sdk = { workspace = true }` has no version in
//! its own manifest. The scanner must resolve the version from the workspace
//! root so SS-015 and SDK reporting see it, while keeping the dependency
//! marked as inherited.

use std::path::PathBuf;

use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::model::DepSource;
use soroban_scan_core::project;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/projects")
        .join(name)
}

#[test]
fn inherited_sdk_version_is_reported_and_stays_inherited() {
    let loaded = project::load(&fixture("nested-workspace"), &DiscoveryOptions::default()).unwrap();

    assert!(
        loaded
            .project
            .soroban
            .sdk_versions
            .iter()
            .any(|version| version == "21.0.0"),
        "inherited soroban-sdk version missing from {:?}",
        loaded.project.soroban.sdk_versions
    );

    let member = loaded
        .project
        .manifests
        .iter()
        .find(|manifest| {
            manifest
                .package
                .as_ref()
                .is_some_and(|package| package.name == "fixture-nested-member")
        })
        .expect("member manifest");
    let inherited = member.dependency("soroban-sdk").expect("member dependency");
    assert_eq!(inherited.version.as_deref(), Some("21.0.0"));
    assert_eq!(inherited.source, DepSource::Workspace);

    let root = loaded
        .project
        .manifests
        .iter()
        .find(|manifest| manifest.is_workspace_root())
        .expect("workspace root manifest");
    let declared = root
        .dependency("soroban-sdk")
        .expect("workspace dependency");
    assert_eq!(declared.source, DepSource::Registry { registry: None });
}
