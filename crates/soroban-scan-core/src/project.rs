//! Project loading: discovery, manifest intelligence, and source parsing.

use std::path::{Path, PathBuf};

use crate::discovery::{self, DiscoveryOptions};
use crate::error::ScanError;
use crate::manifest;
use crate::model::{Diagnostic, DiagnosticCode, Project};
use crate::soroban;
use crate::source::{self, ParsedSource};

/// A fully loaded project: metadata plus parsed sources.
pub struct LoadedProject {
    /// Project metadata.
    pub project: Project,
    /// Parsed Rust source files.
    pub sources: Vec<ParsedSource>,
    /// Generated source files excluded before analysis.
    pub generated_files_excluded: usize,
}

/// Loads a project, including parsed sources and Soroban evidence.
///
/// Malformed nested manifests and unparseable source files are reported as
/// diagnostics rather than aborting the scan. The root manifest, if present and
/// unreadable, is an error.
pub fn load(root: &Path, opts: &DiscoveryOptions) -> Result<LoadedProject, ScanError> {
    let discovered = discovery::discover(root, opts)?;
    let mut manifests = Vec::new();
    let mut diagnostics = Vec::new();

    for path in &discovered.manifests {
        match manifest::load_manifest(path) {
            Ok(manifest) => manifests.push(manifest),
            Err(err) => {
                let is_root_manifest = path.parent() == Some(root);
                if is_root_manifest {
                    return Err(err);
                }
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::ManifestUnreadable,
                    format!("skipping unreadable manifest: {err}"),
                    Some(path.clone()),
                ));
            }
        }
    }

    manifest::resolve_workspace_dependencies(&mut manifests);

    let loaded = source::load_sources_with_options(
        &discovered.rust_files,
        &manifests,
        root,
        source::SourceOptions {
            exclude_tests: opts.exclude_tests || !opts.include_cfg_test,
            exclude_generated: opts.exclude_generated,
        },
    );
    let sources = loaded.sources;
    diagnostics.extend(loaded.diagnostics);

    let soroban = soroban::analyze_manifests(&manifests);
    let mut project = Project {
        root: root.to_path_buf(),
        kind: soroban::classify(&soroban),
        manifests,
        soroban,
        source_files: discovered.rust_files.len(),
        diagnostics,
    };
    source::apply_source_evidence(&mut project, &sources);

    Ok(LoadedProject {
        project,
        sources,
        generated_files_excluded: loaded.generated_files_excluded,
    })
}

/// Loads only project metadata (no parsed sources).
pub fn load_project(root: &Path, opts: &DiscoveryOptions) -> Result<Project, ScanError> {
    load(root, opts).map(|loaded| loaded.project)
}

/// Loads a specific set of source files without full directory discovery.
///
/// Used when scanning individual files. The root manifest, if present, is
/// consulted for Soroban dependency evidence.
pub fn load_files(root: &Path, files: &[PathBuf]) -> Result<LoadedProject, ScanError> {
    load_files_with_options(root, files, &DiscoveryOptions::default())
}

/// Loads a specific set of source files with discovery options.
///
/// Used when scanning individual files with `--exclude-tests`; the options
/// control whether `#[cfg(test)]` items are pruned from parsed sources.
pub fn load_files_with_options(
    root: &Path,
    files: &[PathBuf],
    opts: &DiscoveryOptions,
) -> Result<LoadedProject, ScanError> {
    let mut manifests = Vec::new();
    let mut diagnostics = Vec::new();

    let root_manifest = root.join("Cargo.toml");
    if root_manifest.is_file() {
        match manifest::load_manifest(&root_manifest) {
            Ok(manifest) => manifests.push(manifest),
            Err(err) => diagnostics.push(Diagnostic::warning(
                DiagnosticCode::ManifestUnreadable,
                format!("skipping unreadable manifest: {err}"),
                Some(root_manifest),
            )),
        }
    }

    manifest::resolve_workspace_dependencies(&mut manifests);

    let loaded = source::load_sources_with_options(
        files,
        &manifests,
        root,
        source::SourceOptions {
            exclude_tests: opts.exclude_tests || !opts.include_cfg_test,
            exclude_generated: opts.exclude_generated,
        },
    );
    let sources = loaded.sources;
    diagnostics.extend(loaded.diagnostics);

    let soroban = soroban::analyze_manifests(&manifests);
    let mut project = Project {
        root: root.to_path_buf(),
        kind: soroban::classify(&soroban),
        manifests,
        soroban,
        source_files: files.len(),
        diagnostics,
    };
    source::apply_source_evidence(&mut project, &sources);

    Ok(LoadedProject {
        project,
        sources,
        generated_files_excluded: loaded.generated_files_excluded,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProjectKind;
    use std::path::PathBuf;

    fn tmpdir(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "soroban-scan-project-{}-{}",
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

    #[test]
    fn classifies_soroban_project() {
        let root = tmpdir("soroban");
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n[dependencies]\nsoroban-sdk = \"21.0.0\"\n",
        );
        write(&root.join("src/lib.rs"), "fn f() {}");
        let project = load_project(&root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(project.kind, ProjectKind::LikelySoroban);
        assert!(project.soroban.has_sdk_dependency);
        assert_eq!(project.source_files, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn confirms_soroban_from_contract_macro() {
        let root = tmpdir("confirmed");
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"c\"\nversion = \"0.1.0\"\n[dependencies]\nsoroban-sdk = \"21.0.0\"\n",
        );
        write(
            &root.join("src/lib.rs"),
            "#[contractimpl]\nimpl C { pub fn f() {} }\n",
        );
        let loaded = load(&root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(loaded.project.kind, ProjectKind::ConfirmedSoroban);
        assert!(loaded.project.soroban.contract_macros_found);
        assert_eq!(loaded.sources.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn resolves_inherited_workspace_sdk_versions() {
        let root = tmpdir("inherited");
        write(
            &root.join("Cargo.toml"),
            "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.dependencies]\nsoroban-sdk = { version = \"21.7.7\", features = [\"alloc\"] }\n",
        );
        write(
            &root.join("crates/member/Cargo.toml"),
            "[package]\nname = \"member\"\nversion = \"0.1.0\"\n\n[dependencies]\nsoroban-sdk = { workspace = true, features = [\"testutils\"] }\n",
        );
        write(&root.join("crates/member/src/lib.rs"), "pub fn f() {}\n");

        let loaded = load(&root, &DiscoveryOptions::default()).unwrap();

        assert!(loaded
            .project
            .soroban
            .sdk_versions
            .contains(&"21.7.7".to_string()));
        let member = loaded
            .project
            .manifests
            .iter()
            .find(|manifest| {
                manifest
                    .package
                    .as_ref()
                    .is_some_and(|package| package.name == "member")
            })
            .unwrap();
        let dependency = member.dependency("soroban-sdk").unwrap();
        assert_eq!(dependency.version.as_deref(), Some("21.7.7"));
        assert_eq!(dependency.source, crate::model::DepSource::Workspace);
        assert_eq!(dependency.features, vec!["alloc", "testutils"]);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn classifies_generic_rust_project() {
        let root = tmpdir("generic");
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"g\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1\"\n",
        );
        let project = load_project(&root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(project.kind, ProjectKind::GenericRust);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_root_manifest_is_fatal() {
        let root = tmpdir("badroot");
        write(&root.join("Cargo.toml"), "not = = toml");
        assert!(load_project(&root, &DiscoveryOptions::default()).is_err());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn invalid_nested_manifest_is_diagnostic() {
        let root = tmpdir("badnested");
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"root\"\nversion = \"0.1.0\"\n",
        );
        write(&root.join("nested/Cargo.toml"), "not = = toml");
        let project = load_project(&root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(project.manifests.len(), 1);
        assert_eq!(project.diagnostics.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unparseable_source_is_diagnostic() {
        let root = tmpdir("badsource");
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\n",
        );
        write(&root.join("src/lib.rs"), "fn broken( {");
        let loaded = load(&root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(loaded.sources.len(), 1);
        assert!(loaded.sources[0].parse_error.is_some());
        assert!(loaded.project.diagnostics.iter().any(
            |d| d.code == DiagnosticCode::ParseFailed && d.message.contains("failed to parse")
        ));
        let _ = std::fs::remove_dir_all(&root);
    }
}
