//! Diagnostics for source kinds outside the Rust frontend.
//!
//! The Rust frontend can only analyze Rust. Files written in another language
//! are ignored rather than partially parsed, so a scan of a mixed repository can
//! silently cover less than the user expects. This module turns those files into
//! bounded diagnostics aggregated by language, without reading or echoing any
//! source text.

use std::collections::BTreeMap;
use std::path::Path;

use crate::model::{Diagnostic, DiagnosticCode};

/// Maximum number of unsupported source kinds reported in one scan.
pub const MAX_UNSUPPORTED_KINDS: usize = 8;

/// Returns the language label for a recognized non-Rust source extension.
pub fn language_for_extension(extension: &str) -> Option<&'static str> {
    match extension.to_ascii_lowercase().as_str() {
        "ts" | "tsx" => Some("TypeScript"),
        "js" | "jsx" | "mjs" | "cjs" => Some("JavaScript"),
        "sol" => Some("Solidity"),
        "py" => Some("Python"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "kt" | "kts" => Some("Kotlin"),
        "c" | "cc" | "cpp" | "cxx" | "hpp" => Some("C/C++"),
        _ => None,
    }
}

/// Records a non-Rust source file by language, if the extension is recognized.
pub fn note_source(counts: &mut BTreeMap<String, usize>, path: &Path) {
    let Some(extension) = path.extension().and_then(|extension| extension.to_str()) else {
        return;
    };
    let Some(language) = language_for_extension(extension) else {
        return;
    };
    *counts.entry(language.to_string()).or_insert(0) += 1;
}

/// Builds one bounded diagnostic per unsupported language kind.
pub fn diagnostics(counts: &BTreeMap<String, usize>) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (language, count) in counts.iter().take(MAX_UNSUPPORTED_KINDS) {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::UnsupportedSyntax,
            format!(
                "{count} {language} source file(s) use syntax the rust frontend does not \
                 support; they were not analyzed"
            ),
            None,
        ));
    }
    let omitted = counts.len().saturating_sub(MAX_UNSUPPORTED_KINDS);
    if omitted > 0 {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::UnsupportedSyntax,
            format!(
                "additional unsupported source kinds omitted (limit {MAX_UNSUPPORTED_KINDS}; \
                 {omitted} kind(s) not listed)"
            ),
            None,
        ));
    }
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn collect(paths: &[&str]) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for path in paths {
            note_source(&mut counts, &PathBuf::from(path));
        }
        counts
    }

    #[test]
    fn aggregates_files_by_language() {
        let counts = collect(&["a.ts", "b.tsx", "c.sol", "README.md", "src/lib.rs"]);
        assert_eq!(counts.get("TypeScript"), Some(&2));
        assert_eq!(counts.get("Solidity"), Some(&1));
        assert_eq!(counts.len(), 2, "unrecognized extensions are ignored");

        let diagnostics = diagnostics(&counts);
        assert_eq!(diagnostics.len(), 2);
        assert!(diagnostics.iter().all(|diagnostic| {
            diagnostic.code == DiagnosticCode::UnsupportedSyntax
                && diagnostic.level == crate::model::DiagnosticLevel::Warning
        }));
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("2 TypeScript")));
    }

    #[test]
    fn bounds_the_number_of_kinds() {
        let mut counts = BTreeMap::new();
        for index in 0..(MAX_UNSUPPORTED_KINDS + 2) {
            counts.insert(format!("language-{index:02}"), 1);
        }
        let diagnostics = diagnostics(&counts);
        assert_eq!(diagnostics.len(), MAX_UNSUPPORTED_KINDS + 1);
        let last = diagnostics.last().unwrap();
        assert!(last.message.contains("omitted"));
        assert!(last.message.contains("limit"));
    }

    #[test]
    fn known_extensions_are_never_flagged() {
        let counts = collect(&["Cargo.toml", "src/lib.rs", "README.md", "data.json"]);
        assert!(counts.is_empty());
        assert!(diagnostics(&counts).is_empty());
    }
}
