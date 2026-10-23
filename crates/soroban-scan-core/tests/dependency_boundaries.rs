//! Crate and module dependency boundaries (#76).
//!
//! The workspace layout document defines the intended dependency direction:
//! `core` must never depend on the `cli` crate, `report` consumes engine
//! results without influencing rule evaluation, and the analysis/leaf modules
//! never reach upward into rendering or orchestration.
//!
//! The checker parses `Cargo.toml` manifests and the `use crate::...` paths in
//! every core source file. It fails closed when a forbidden edge appears.
//!
//! Deliberately failing examples (never add these to the code):
//!
//! ```ignore
//! // In crates/soroban-scan-core/src/engine.rs:
//! use crate::report::render_json; // forbidden: engine -> report
//!
//! // Anywhere in crates/soroban-scan-core:
//! use soroban_scan_cli::run; // forbidden: core -> CLI
//! ```
//!
//! Those examples are exercised by `checker_flags_deliberately_failing_examples`
//! so the guard is proven to reject them without needing to break the build.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

fn core_sources(root: &Path) -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let relative = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let owner = relative
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(".rs")
                    .to_string();
                out.push((owner, read(&path)));
            }
        }
    }

    let src = root.join("crates/soroban-scan-core/src");
    let mut out = Vec::new();
    walk(&src, &src, &mut out);
    out
}

/// Returns every module named by a `use crate::...` path in `content`.
fn crate_imports(content: &str) -> BTreeSet<String> {
    let mut imports = BTreeSet::new();
    for raw in content.lines() {
        let line = raw.trim_start();
        let rest = line
            .strip_prefix("pub(crate) use crate::")
            .or_else(|| line.strip_prefix("pub use crate::"))
            .or_else(|| line.strip_prefix("use crate::"));
        let Some(rest) = rest else { continue };

        for token in rest.split(|character: char| {
            character.is_whitespace() || matches!(character, '{' | '}' | ',' | ';' | '*')
        }) {
            let name = token.split("::").next().unwrap_or("").trim();
            if !name.is_empty() && name != "self" && name != "super" {
                imports.insert(name.to_string());
            }
        }
    }
    imports
}

/// Returns `true` when `content` names the CLI crate.
fn cli_references(content: &str) -> bool {
    content.contains("soroban_scan_cli") || content.contains("soroban-scan-cli")
}

/// Documented edges that must never exist.
fn forbidden_edge(owner: &str, target: &str) -> bool {
    matches!(
        (owner, target),
        ("engine", "report")
            | ("engine", "baseline")
            | ("baseline", "engine")
            | ("baseline", "report")
            | ("finding", "engine")
            | ("finding", "report")
            | ("finding", "project")
            | ("rules", "report")
            | ("rules", "baseline")
    )
}

fn violations(owner: &str, content: &str) -> Vec<String> {
    crate_imports(content)
        .into_iter()
        .filter(|target| forbidden_edge(owner, target))
        .map(|target| format!("{owner} -> {target}"))
        .collect()
}

#[test]
fn core_crate_does_not_depend_on_the_cli() {
    let root = repo_root();
    let manifest = read(&root.join("crates/soroban-scan-core/Cargo.toml"));
    assert!(
        !cli_references(&manifest),
        "soroban-scan-core/Cargo.toml must not depend on soroban-scan-cli"
    );

    for (owner, content) in core_sources(&root) {
        assert!(
            !cli_references(&content),
            "core source {owner} references the CLI crate; core must not depend on the CLI"
        );
    }
}

#[test]
fn cli_crate_depends_on_the_core() {
    let manifest = read(&repo_root().join("crates/soroban-scan-cli/Cargo.toml"));
    assert!(
        manifest.contains("soroban-scan-core"),
        "the CLI crate must depend on soroban-scan-core"
    );
}

#[test]
fn report_crate_depends_on_engine() {
    let report = read(&repo_root().join("crates/soroban-scan-core/src/report/mod.rs"));
    assert!(
        crate_imports(&report).contains("engine"),
        "report must consume engine results (report -> engine)"
    );
}

#[test]
fn documented_module_directions_hold() {
    let root = repo_root();
    let mut found = Vec::new();
    for (owner, content) in core_sources(&root) {
        for violation in violations(&owner, &content) {
            found.push(format!("{owner}: {violation}"));
        }
    }

    assert!(
        found.is_empty(),
        "forbidden module dependency edge(s) found:\n  {}\n\
         See docs/architecture/workspace-layout.md for the documented directions",
        found.join("\n  ")
    );
}

#[test]
fn checker_flags_deliberately_failing_examples() {
    assert_eq!(
        violations("engine", "use crate::report::render_json;"),
        vec!["engine -> report".to_string()],
        "the checker must reject engine -> report"
    );
    assert_eq!(
        violations("baseline", "use crate::engine::ScanOutcome;"),
        vec!["baseline -> engine".to_string()],
        "the checker must reject baseline -> engine"
    );
    assert!(
        cli_references("use soroban_scan_cli::run;"),
        "the checker must reject a core -> CLI reference"
    );
    assert!(
        violations("report", "use crate::engine::ScanOutcome;").is_empty(),
        "report -> engine is the documented direction and must be allowed"
    );
}
