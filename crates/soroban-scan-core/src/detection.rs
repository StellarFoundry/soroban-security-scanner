//! Language and project-type detection evidence.
//!
//! Detection is deliberately conservative: only the Rust frontend ships today,
//! and incomplete evidence is marked `weak` instead of being guessed at. The
//! manifest contains only relative paths and short labels; never source text,
//! environment values, or secrets.

use std::collections::BTreeSet;
use std::path::Path;

use crate::frontend::RUST_LANGUAGE;
use crate::model::{DetectionConfidence, DetectionEvidence, DetectionInfo, Manifest, SorobanInfo};
use crate::soroban;
use crate::source::ParsedSource;

/// Upper bound on evidence records, keeping the manifest small.
pub const MAX_DETECTION_EVIDENCE: usize = 32;

/// Builds the detection manifest from already-loaded project data.
pub fn detect(
    root: &Path,
    manifests: &[Manifest],
    sources: &[ParsedSource],
    soroban: &SorobanInfo,
    source_files: usize,
) -> DetectionInfo {
    let has_manifest = !manifests.is_empty();
    let has_source = source_files > 0;
    let language = if has_manifest || has_source {
        RUST_LANGUAGE
    } else {
        "unknown"
    };

    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    let mut push = |kind: &str, path: Option<String>, detail: String| {
        if seen.insert((kind.to_string(), path.clone(), detail.clone())) {
            evidence.push(DetectionEvidence {
                kind: kind.to_string(),
                path,
                detail,
            });
        }
    };

    for manifest in manifests {
        let path = relative_label(root, &manifest.path);
        push("manifest", Some(path), "Cargo.toml manifest".to_string());
    }
    if has_source {
        let path = sources
            .first()
            .map(|source| relative_label(root, &source.path));
        push(
            "source",
            path,
            format!("{source_files} Rust source file(s) discovered"),
        );
    }
    for manifest in manifests {
        let path = relative_label(root, &manifest.path);
        for dependency in &manifest.dependencies {
            if soroban::is_soroban_dependency(&dependency.name) {
                push(
                    "dependency",
                    Some(path.clone()),
                    format!("Soroban dependency `{}` declared", dependency.name),
                );
            }
        }
    }
    if soroban.contract_macros_found {
        push(
            "contract-macro",
            None,
            "contract definition attribute found".to_string(),
        );
    }

    evidence.sort_by(|a, b| {
        (a.kind.as_str(), a.path.as_deref(), a.detail.as_str()).cmp(&(
            b.kind.as_str(),
            b.path.as_deref(),
            b.detail.as_str(),
        ))
    });
    if evidence.len() > MAX_DETECTION_EVIDENCE {
        evidence.truncate(MAX_DETECTION_EVIDENCE - 1);
        evidence.push(DetectionEvidence {
            kind: "limit".to_string(),
            path: None,
            detail: format!("additional evidence omitted (limit {MAX_DETECTION_EVIDENCE})"),
        });
    }

    DetectionInfo {
        frontend: if language == RUST_LANGUAGE {
            RUST_LANGUAGE.to_string()
        } else {
            "unknown".to_string()
        },
        language: language.to_string(),
        project_type: if language == RUST_LANGUAGE {
            soroban::classify(soroban).as_str().to_string()
        } else {
            "unknown".to_string()
        },
        confidence: if language == RUST_LANGUAGE && has_manifest && has_source {
            DetectionConfidence::Strong
        } else {
            DetectionConfidence::Weak
        },
        evidence,
    }
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
