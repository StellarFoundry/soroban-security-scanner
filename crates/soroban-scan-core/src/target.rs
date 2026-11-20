//! Static Cargo target analysis.
//!
//! This module reads declared targets from `Cargo.toml` manifests and
//! `.cargo/config[.toml]`. It never invokes Cargo, builds, or executes the
//! project. Only wasm32 targets are understood; any other explicit target is
//! reported as unsupported instead of being guessed at.
//!
//! Target-specific dependencies are tagged during manifest parsing. When an
//! explicit target is configured, dependencies scoped to a different target are
//! removed before rule evaluation, so host-only dependencies cannot produce
//! false Soroban dependency findings in a wasm build.

use std::collections::BTreeSet;
use std::path::Path;

use crate::discovery::MAX_CARGO_CONFIG_BYTES;
use crate::model::{Diagnostic, DiagnosticCode, Manifest, TargetInfo};

/// Reads target configuration and returns the result plus diagnostics.
pub fn analyze(root: &Path, manifests: &[Manifest]) -> (TargetInfo, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let mut evidence = Vec::new();
    let mut targets = BTreeSet::new();
    let mut requested: Option<String> = None;
    let mut crate_types = BTreeSet::new();

    for name in [".cargo/config.toml", ".cargo/config"] {
        let path = root.join(name);
        if !path.is_file() {
            continue;
        }
        let label = relative_label(root, &path);
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::TargetConfigUnreadable,
                    format!("cannot read {label}: {error}; target analysis skipped for it"),
                    Some(path),
                ));
                continue;
            }
        };
        if metadata.len() > MAX_CARGO_CONFIG_BYTES {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::TargetConfigUnreadable,
                format!("{label} exceeds the size limit; target analysis skipped for it"),
                Some(path),
            ));
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::TargetConfigUnreadable,
                    format!("cannot read {label}: {error}; target analysis skipped for it"),
                    Some(path),
                ));
                continue;
            }
        };
        let value: toml::Value = match toml::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::TargetConfigUnreadable,
                    format!("invalid {label}: {error}; target analysis skipped for it"),
                    Some(path),
                ));
                continue;
            }
        };

        if requested.is_none() {
            if let Some(target) = value
                .get("build")
                .and_then(toml::Value::as_table)
                .and_then(|build| build.get("target"))
                .and_then(toml::Value::as_str)
            {
                requested = Some(target.to_string());
                evidence.push(format!("{label} sets build.target = `{target}`"));
            }
        }
        if let Some(table) = value.get("target").and_then(toml::Value::as_table) {
            for key in table.keys() {
                targets.insert(key.clone());
                evidence.push(format!("{label} configures target `{key}`"));
            }
        }
    }

    for manifest in manifests {
        let label = relative_label(root, &manifest.path);
        for target in manifest
            .dependencies
            .iter()
            .filter_map(|dependency| dependency.target.as_deref())
        {
            if targets.insert(target.to_string()) {
                evidence.push(format!("{label} declares target `{target}`"));
            }
        }
        for crate_type in &manifest.crate_types {
            if crate_types.insert(crate_type.clone()) {
                evidence.push(format!("{label} declares crate-type `{crate_type}`"));
            }
        }
    }

    // An explicit target wins; target tables alone only imply wasm when no
    // explicit target was configured.
    let wasm32 = match requested.as_deref() {
        Some(target) => target.starts_with("wasm32"),
        None => targets.iter().any(|target| target.contains("wasm32")),
    };
    let supported = requested
        .as_deref()
        .is_none_or(|target| target.starts_with("wasm32"));

    evidence.sort();
    evidence.dedup();

    let info = TargetInfo {
        requested: requested.clone(),
        wasm32,
        supported,
        crate_types: crate_types.into_iter().collect(),
        targets: targets.into_iter().collect(),
        evidence,
    };

    match requested.as_deref() {
        Some(target) if !supported => diagnostics.push(Diagnostic::warning(
            DiagnosticCode::TargetUnsupported,
            format!(
                "unsupported target analysis for `{target}`; only wasm32 targets are \
                 analyzed. Target-specific dependencies were filtered from static analysis \
                 and the scanner did not build the project"
            ),
            None,
        )),
        Some(target) => diagnostics.push(Diagnostic::info(
            DiagnosticCode::TargetDetected,
            format!(
                "wasm32 target `{target}` detected; target-specific dependencies were \
                 filtered and the scanner did not build or execute the project"
            ),
            None,
        )),
        None if wasm32 => diagnostics.push(Diagnostic::info(
            DiagnosticCode::TargetDetected,
            "wasm32 target table detected; target-specific dependencies were filtered and \
             the scanner did not build or execute the project"
                .to_string(),
            None,
        )),
        None => {}
    }

    (info, diagnostics)
}

/// Removes dependencies scoped to a different explicit target.
///
/// A dependency declared under `[target.<key>.dependencies]` is removed when
/// the configured target clearly does not match `key`. Unknown cfg expressions
/// are kept, because guessing could hide a real dependency.
pub fn filter_dependencies(manifests: &mut [Manifest], info: &TargetInfo) {
    let Some(requested) = info.requested.as_deref() else {
        return;
    };
    for manifest in manifests {
        manifest
            .dependencies
            .retain(|dependency| match dependency.target.as_deref() {
                None => true,
                Some(scope) => target_matches(scope, requested),
            });
    }
}

/// Returns true when a target table key clearly matches the configured target.
fn target_matches(scope: &str, target: &str) -> bool {
    let scope = scope.trim();
    if scope == target {
        return true;
    }
    let target_is_wasm = target.starts_with("wasm32");
    let compact: String = scope.chars().filter(|c| !c.is_whitespace()).collect();
    if !compact.contains("wasm32") {
        return if compact.contains('(') {
            true
        } else {
            compact == target
        };
    }
    let negated = compact.contains("not(target_arch=\"wasm32\")");
    if negated {
        !target_is_wasm
    } else {
        target_is_wasm
    }
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cfg_matching_is_conservative() {
        assert!(target_matches(
            "wasm32-unknown-unknown",
            "wasm32-unknown-unknown"
        ));
        assert!(target_matches(
            "cfg(target_arch = \"wasm32\")",
            "wasm32-unknown-unknown"
        ));
        assert!(!target_matches(
            "cfg(not(target_arch = \"wasm32\"))",
            "wasm32-unknown-unknown"
        ));
        assert!(target_matches(
            "cfg(not(target_arch = \"wasm32\"))",
            "x86_64-unknown-linux-gnu"
        ));
        assert!(!target_matches(
            "x86_64-unknown-linux-gnu",
            "wasm32-unknown-unknown"
        ));
        // Unknown feature cfg is kept rather than guessed away.
        assert!(target_matches(
            "cfg(feature = \"extra\")",
            "wasm32-unknown-unknown"
        ));
    }
}
