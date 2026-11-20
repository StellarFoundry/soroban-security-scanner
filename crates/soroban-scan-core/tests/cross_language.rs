//! Cross-language fixtures (#385).
//!
//! A valid project in another language is unsupported input. It must fail
//! cleanly, without a panic, a partial parse, or a fabricated Soroban project.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;

use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::model::{DiagnosticCode, ProjectKind};
use soroban_scan_core::project::{self, LoadedProject};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cross-language")
        .join(name)
}

fn with_unsupported_syntax() -> DiscoveryOptions {
    DiscoveryOptions {
        unsupported_syntax: true,
        ..DiscoveryOptions::default()
    }
}

fn load_safely(root: &std::path::Path, opts: &DiscoveryOptions) -> LoadedProject {
    catch_unwind(AssertUnwindSafe(|| project::load(root, opts)))
        .expect("loading an unsupported language must not panic")
        .expect("an unsupported language is a diagnostic, not a fatal error")
}

fn syntax_messages(loaded: &LoadedProject) -> Vec<&str> {
    loaded
        .project
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == DiagnosticCode::UnsupportedSyntax)
        .map(|diagnostic| diagnostic.message.as_str())
        .collect()
}

#[test]
fn typescript_project_is_skipped_with_a_diagnostic() {
    let loaded = load_safely(&fixture("typescript-soroban"), &with_unsupported_syntax());

    assert_eq!(loaded.project.source_files, 0);
    assert!(loaded.sources.is_empty(), "no partial parsing");
    assert!(loaded.project.manifests.is_empty());
    assert_eq!(loaded.project.kind, ProjectKind::GenericRust);
    assert_eq!(loaded.project.detection.language, "unknown");

    let messages = syntax_messages(&loaded);
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("2 TypeScript"));
    assert!(messages[0].contains("not analyzed"));
    assert!(!messages[0].contains("deposit"), "no source text");
}

#[test]
fn solidity_project_is_skipped_with_a_diagnostic() {
    let loaded = load_safely(&fixture("solidity-vault"), &with_unsupported_syntax());

    assert_eq!(loaded.project.source_files, 0);
    assert!(loaded.sources.is_empty());
    let messages = syntax_messages(&loaded);
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("1 Solidity"));
    assert!(!messages[0].contains("balances"), "no source text");
}

#[test]
fn plain_cargo_project_is_supported_and_not_flagged() {
    let loaded = load_safely(&fixture("plain-cargo"), &with_unsupported_syntax());

    assert_eq!(loaded.project.kind, ProjectKind::GenericRust);
    assert_eq!(loaded.project.source_files, 1);
    assert_eq!(loaded.sources.len(), 1);
    assert_eq!(loaded.project.detection.language, "rust");
    assert!(syntax_messages(&loaded).is_empty());
}

#[test]
fn cross_language_input_is_quiet_without_the_opt_in() {
    for name in ["typescript-soroban", "solidity-vault"] {
        let loaded = load_safely(&fixture(name), &DiscoveryOptions::default());
        assert!(syntax_messages(&loaded).is_empty());
    }
}
