//! Parser-failure corpus.
//!
//! `fixtures/parser-failures/*.rs` are deliberately malformed Rust sources
//! (truncated tokens, unbalanced delimiters, unterminated strings). Each one
//! must make `syn` fail to parse; the scanner must record a "failed to parse
//! source" diagnostic and never panic. This shared, growing corpus protects
//! the untrusted-input posture that the adversarial tests also cover.

use std::path::{Path, PathBuf};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

fn parser_failures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/parser-failures")
}

/// Scans `src` and returns the parse diagnostics for it.
fn parse_diagnostics(src: &str, file_name: &str) -> Vec<soroban_scan_core::model::Diagnostic> {
    let registry = RuleRegistry::with_default_rules();
    let outcome = engine::scan_source_str(src, file_name, &ScanConfig::default(), &registry);
    outcome
        .diagnostics
        .into_iter()
        .filter(|d| d.message.contains("failed to parse source"))
        .collect()
}

#[test]
fn parser_failure_corpus_is_exercised_and_does_not_panic() {
    let dir = parser_failures_dir();
    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("missing parser-failures corpus dir {:?}: {e}", dir));

    let mut samples: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let entry = entry.expect("failed to read dir entry");
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !path.is_file() || !name.ends_with(".rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        samples.push((name.to_string(), src));
    }

    assert!(
        !samples.is_empty(),
        "the parser-failures corpus must contain at least one sample"
    );

    for (name, src) in samples {
        let diagnostics = parse_diagnostics(&src, &name);
        assert!(
            !diagnostics.is_empty(),
            "{name}: expected a 'failed to parse source' diagnostic, got none"
        );
        assert!(
            diagnostics
                .iter()
                .any(|d| d.path.as_deref() == Some(std::path::Path::new(&name))),
            "{name}: diagnostic should carry the source file name"
        );
    }
}
