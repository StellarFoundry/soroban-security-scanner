//! Reusable frontend conformance harness (#386).
//!
//! A future frontend can include this module from its own integration test and
//! call [`check`] with a valid fixture and a fixture that fails to parse. The
//! harness returns every failed behaviour instead of stopping at the first
//! mismatch, so one run reports the full conformance gap.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use soroban_scan_core::discovery::{Discovered, DiscoveryOptions};
use soroban_scan_core::frontend::Frontend;
use soroban_scan_core::model::{DiagnosticCode, DiagnosticLevel};
use soroban_scan_core::project::LoadedProject;

/// One frontend plus the fixtures used to exercise the trait contract.
pub struct Case<'a> {
    /// Frontend under test.
    pub frontend: &'a dyn Frontend,
    /// Expected `Frontend::name()` value.
    pub expected_name: &'a str,
    /// A valid project fixture the frontend must load.
    pub root: &'a Path,
    /// A fixture with at least one unparseable source file.
    pub broken_root: &'a Path,
}

/// Runs every conformance check, returning human-readable failures.
pub fn check(case: &Case<'_>) -> Vec<String> {
    let mut failures = Vec::new();
    let opts = DiscoveryOptions::default();

    let name = case.frontend.name();
    if name.trim().is_empty() || !name.chars().all(|c| c.is_ascii_lowercase()) {
        failures.push(format!(
            "name: expected a stable lowercase language, got {name:?}"
        ));
    }
    if name != case.expected_name {
        failures.push(format!(
            "name: expected {:?}, got {name:?}",
            case.expected_name
        ));
    }

    let discovered = match case.frontend.discover(case.root, &opts) {
        Ok(discovered) => discovered,
        Err(error) => {
            failures.push(format!("discover: valid fixture failed: {error}"));
            return failures;
        }
    };
    check_discovery(case.frontend, case.root, &opts, &discovered, &mut failures);

    let loaded = match case.frontend.load(case.root, &opts) {
        Ok(loaded) => loaded,
        Err(error) => {
            failures.push(format!("load: valid fixture failed: {error}"));
            return failures;
        }
    };
    check_loaded(case.root, &discovered, &loaded, name, &mut failures);
    check_items_and_spans(&loaded, &mut failures);

    let loaded_again = match case.frontend.load(case.root, &opts) {
        Ok(loaded) => loaded,
        Err(error) => {
            failures.push(format!("load: second call failed: {error}"));
            return failures;
        }
    };
    check_deterministic(&loaded, &loaded_again, &mut failures);

    check_load_files(case, &discovered, &loaded, &mut failures);
    check_broken_fixture(case, &opts, &mut failures);

    failures
}

fn check_discovery(
    frontend: &dyn Frontend,
    root: &Path,
    opts: &DiscoveryOptions,
    discovered: &Discovered,
    failures: &mut Vec<String>,
) {
    if discovered.manifests.is_empty() {
        failures.push("discover: no manifests found in the valid fixture".to_string());
    }
    if discovered.rust_files.is_empty() {
        failures.push("discover: no source files found in the valid fixture".to_string());
    }
    for path in discovered.manifests.iter().chain(&discovered.rust_files) {
        if path.strip_prefix(root).is_err() {
            failures.push(format!(
                "discover: returned a path outside the scan root: {}",
                path.display()
            ));
        }
    }

    match frontend.discover(root, opts) {
        Ok(again) if &again == discovered => {}
        Ok(_) => failures.push("discover: repeated calls differ".to_string()),
        Err(error) => failures.push(format!("discover: repeated call failed: {error}")),
    }

    let missing = root.join("conformance-fixture-does-not-exist");
    if frontend.discover(&missing, opts).is_ok() {
        failures.push("discover: missing root returned Ok".to_string());
    }
}

fn check_loaded(
    root: &Path,
    discovered: &Discovered,
    loaded: &LoadedProject,
    name: &str,
    failures: &mut Vec<String>,
) {
    if loaded.project.root != root {
        failures.push(format!(
            "load: project.root is {:?}, expected {:?}",
            loaded.project.root, root
        ));
    }
    if loaded.project.source_files != discovered.rust_files.len() {
        failures.push(format!(
            "load: source_files is {}, expected {}",
            loaded.project.source_files,
            discovered.rust_files.len()
        ));
    }
    if loaded.sources.len() != discovered.rust_files.len() {
        failures.push(format!(
            "load: loaded {} source(s), discovery found {}",
            loaded.sources.len(),
            discovered.rust_files.len()
        ));
    }
    let discovered_paths: BTreeSet<PathBuf> = discovered.rust_files.iter().cloned().collect();
    let loaded_paths: BTreeSet<PathBuf> = loaded
        .sources
        .iter()
        .map(|source| source.path.clone())
        .collect();
    if discovered_paths != loaded_paths {
        failures.push("load: loaded source paths differ from discovery".to_string());
    }
    if loaded.project.detection.frontend != name {
        failures.push(format!(
            "load: detection.frontend is {:?}, expected {name:?}",
            loaded.project.detection.frontend
        ));
    }
    if loaded.project.detection.language != name {
        failures.push(format!(
            "load: detection.language is {:?}, expected {name:?}",
            loaded.project.detection.language
        ));
    }
    if loaded.project.manifests.is_empty() {
        failures.push("load: project.manifests is empty".to_string());
    }
}

fn check_items_and_spans(loaded: &LoadedProject, failures: &mut Vec<String>) {
    let mut functions = 0usize;
    let mut items = 0usize;

    for source in &loaded.sources {
        if let Some(error) = &source.parse_error {
            failures.push(format!(
                "items: valid fixture source {:?} did not parse: {error}",
                source.path
            ));
            continue;
        }
        if source.syntax.is_none() {
            failures.push(format!(
                "items: {:?} has no syntax tree but no parse error",
                source.path
            ));
        }
        if source.module_path.trim().is_empty() {
            failures.push(format!("items: {:?} has an empty module path", source.path));
        }

        functions += source.functions.len();
        items += source.items.len();
        for function in &source.functions {
            if function.qualified_name.trim().is_empty() {
                failures.push(format!(
                    "items: {:?}:{} has an empty qualified name",
                    source.path, function.line
                ));
            }
            if function.line == 0 || function.column == 0 {
                failures.push(format!(
                    "items: {:?} function {} has a zero origin",
                    source.path, function.name
                ));
            }
            if function.end_line < function.line {
                failures.push(format!(
                    "items: {:?} function {} ends before it starts",
                    source.path, function.name
                ));
            }
        }
        for item in &source.items {
            if item.line == 0 || item.column == 0 {
                failures.push(format!(
                    "items: {:?} item {:?} has a zero origin",
                    source.path, item.name
                ));
            }
            if item.end_line < item.line {
                failures.push(format!(
                    "items: {:?} item {:?} ends before it starts",
                    source.path, item.name
                ));
            }
        }
        for definition in &source.contract_definitions {
            let valid = definition
                .rsplit_once(':')
                .is_some_and(|(path, line)| !path.is_empty() && line.parse::<usize>().is_ok());
            if !valid {
                failures.push(format!(
                    "items: {:?} has a malformed contract definition {:?}",
                    source.path, definition
                ));
            }
        }
    }

    if functions == 0 {
        failures.push("items: valid fixture produced no functions".to_string());
    }
    if items == 0 {
        failures.push("items: valid fixture produced no items".to_string());
    }
}

fn check_deterministic(first: &LoadedProject, second: &LoadedProject, failures: &mut Vec<String>) {
    if first.project.kind != second.project.kind
        || first.project.detection != second.project.detection
        || first.project.soroban != second.project.soroban
    {
        failures.push("load: repeated calls returned different project metadata".to_string());
    }
    let first_functions: Vec<_> = first
        .sources
        .iter()
        .flat_map(|source| source.functions.iter().map(|f| f.qualified_name.clone()))
        .collect();
    let second_functions: Vec<_> = second
        .sources
        .iter()
        .flat_map(|source| source.functions.iter().map(|f| f.qualified_name.clone()))
        .collect();
    if first_functions != second_functions {
        failures.push("load: repeated calls returned different functions".to_string());
    }
}

fn check_load_files(
    case: &Case<'_>,
    discovered: &Discovered,
    loaded: &LoadedProject,
    failures: &mut Vec<String>,
) {
    match case.frontend.load_files(
        case.root,
        &discovered.rust_files,
        &DiscoveryOptions::default(),
    ) {
        Ok(files) => {
            if files.sources.len() != loaded.sources.len() {
                failures.push(format!(
                    "load_files: loaded {} source(s), load loaded {}",
                    files.sources.len(),
                    loaded.sources.len()
                ));
            }
            if files.project.kind != loaded.project.kind {
                failures.push("load_files: classification differs from load".to_string());
            }
        }
        Err(error) => failures.push(format!("load_files: valid files failed: {error}")),
    }
}

fn check_broken_fixture(case: &Case<'_>, opts: &DiscoveryOptions, failures: &mut Vec<String>) {
    let loaded = match case.frontend.load(case.broken_root, opts) {
        Ok(loaded) => loaded,
        Err(error) => {
            failures.push(format!(
                "diagnostics: unparseable fixture aborted the load: {error}"
            ));
            return;
        }
    };

    let has_parse_diagnostic = loaded.project.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == DiagnosticCode::ParseFailed
            && diagnostic.level == DiagnosticLevel::Warning
    });
    if !has_parse_diagnostic {
        failures.push("diagnostics: no PARSE-001 warning for an unparseable file".to_string());
    }
    if loaded
        .sources
        .iter()
        .all(|source| source.parse_error.is_none())
    {
        failures.push("diagnostics: no source retained its parse error".to_string());
    }
}
