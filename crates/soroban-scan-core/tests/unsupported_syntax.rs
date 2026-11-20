//! Unsupported-syntax diagnostics (#387).
//!
//! The Rust frontend skips files written in other languages. With the opt-in
//! check enabled, those skips become bounded diagnostics aggregated by
//! language, never source text.

use std::path::{Path, PathBuf};

use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::model::{DiagnosticCode, DiagnosticLevel};
use soroban_scan_core::project;

fn tmpdir(name: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "soroban-scan-unsupported-{}-{}",
        name,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn write(path: &Path, content: &str) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

fn with_unsupported_syntax() -> DiscoveryOptions {
    DiscoveryOptions {
        unsupported_syntax: true,
        ..DiscoveryOptions::default()
    }
}

fn syntax_diagnostics(
    loaded: &project::LoadedProject,
) -> Vec<&soroban_scan_core::model::Diagnostic> {
    loaded
        .project
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::UnsupportedSyntax)
        .collect()
}

#[test]
fn aggregates_files_by_language_and_ignores_source_text() {
    let root = tmpdir("aggregate");
    write(
        &root.join("Cargo.toml"),
        "[package]\nname = \"mixed\"\nversion = \"0.1.0\"\n",
    );
    write(&root.join("src/lib.rs"), "pub fn f() {}\n");
    write(&root.join("web/a.ts"), "const secret = \"hunter2\";\n");
    write(&root.join("web/b.tsx"), "export const B = () => null;\n");
    write(
        &root.join("contracts/Vault.sol"),
        "contract Vault { function f() public {} }\n",
    );
    write(&root.join("README.md"), "docs\n");

    let loaded = project::load(&root, &with_unsupported_syntax()).unwrap();
    let diagnostics = syntax_diagnostics(&loaded);

    assert_eq!(diagnostics.len(), 2, "one diagnostic per language kind");
    assert!(diagnostics
        .iter()
        .all(|diagnostic| diagnostic.level == DiagnosticLevel::Warning));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("2 TypeScript")));
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("1 Solidity")));
    assert!(diagnostics
        .iter()
        .all(|diagnostic| !diagnostic.message.contains("hunter2")));
    assert_eq!(loaded.project.source_files, 1, "only Rust is analyzed");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn the_check_is_opt_in() {
    let root = tmpdir("opt-in");
    write(&root.join("web/a.ts"), "export const a = 1;\n");

    let loaded = project::load(&root, &DiscoveryOptions::default()).unwrap();
    assert!(syntax_diagnostics(&loaded).is_empty());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn known_rust_inputs_are_not_flagged() {
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/projects/soroban-confirmed");
    let loaded = project::load(&root, &with_unsupported_syntax()).unwrap();
    assert!(syntax_diagnostics(&loaded).is_empty());
}

#[test]
fn diagnostics_are_exposed_in_json() {
    let root = tmpdir("json");
    write(&root.join("web/a.ts"), "export const a = 1;\n");

    let loaded = project::load(&root, &with_unsupported_syntax()).unwrap();
    let json = serde_json::to_value(&loaded.project).unwrap();
    assert!(json["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "SYNTAX-001"));

    let _ = std::fs::remove_dir_all(&root);
}
