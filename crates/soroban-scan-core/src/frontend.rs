//! Parser frontend boundary.
//!
//! A frontend owns project discovery and item extraction for one language. The
//! engine loads projects through this trait, so adding a language does not
//! require changing the rule pipeline. Only the Rust frontend ships today; no
//! other language is promised or detected.
//!
//! Frontends are deliberately bounded: they may read files below the scan root
//! and parse them, but they must never execute, build, fetch, or mutate scanned
//! code. The trait exposes no I/O beyond the scan-root parameters.

use std::path::{Path, PathBuf};

use crate::discovery::{self, Discovered, DiscoveryOptions};
use crate::error::ScanError;
use crate::project;

pub use crate::project::LoadedProject;

/// Discovery and item extraction for one source language.
pub trait Frontend {
    /// Stable lowercase language name used in reports.
    fn name(&self) -> &'static str;

    /// Discovers manifests and source files below `root`.
    fn discover(&self, root: &Path, opts: &DiscoveryOptions) -> Result<Discovered, ScanError>;

    /// Loads a project and extracts parseable items from every source file.
    fn load(&self, root: &Path, opts: &DiscoveryOptions) -> Result<LoadedProject, ScanError>;

    /// Loads a specific set of files instead of walking `root`.
    fn load_files(
        &self,
        root: &Path,
        files: &[PathBuf],
        opts: &DiscoveryOptions,
    ) -> Result<LoadedProject, ScanError>;
}

/// The default Rust frontend.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RustFrontend;

impl Frontend for RustFrontend {
    fn name(&self) -> &'static str {
        "rust"
    }

    fn discover(&self, root: &Path, opts: &DiscoveryOptions) -> Result<Discovered, ScanError> {
        discovery::discover(root, opts)
    }

    fn load(&self, root: &Path, opts: &DiscoveryOptions) -> Result<LoadedProject, ScanError> {
        project::load(root, opts)
    }

    fn load_files(
        &self,
        root: &Path,
        files: &[PathBuf],
        opts: &DiscoveryOptions,
    ) -> Result<LoadedProject, ScanError> {
        project::load_files_with_options(root, files, opts)
    }
}

/// Returns the default frontend.
pub fn default_frontend() -> RustFrontend {
    RustFrontend
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProjectKind;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/projects")
            .join(name)
    }

    #[test]
    fn rust_frontend_is_the_default_and_object_safe() {
        let frontend: &dyn Frontend = &default_frontend();
        assert_eq!(frontend.name(), "rust");
    }

    #[test]
    fn rust_frontend_discovers_manifests_and_sources() {
        let root = fixture("generic-rust");
        let found = default_frontend()
            .discover(&root, &DiscoveryOptions::default())
            .unwrap();
        assert_eq!(found.manifests.len(), 1);
        assert_eq!(found.rust_files.len(), 1);
    }

    #[test]
    fn rust_frontend_load_matches_project_load() {
        let root = fixture("soroban-confirmed");
        let opts = DiscoveryOptions::default();
        let via_frontend = default_frontend().load(&root, &opts).unwrap();
        let direct = project::load(&root, &opts).unwrap();

        assert_eq!(via_frontend.project.kind, ProjectKind::ConfirmedSoroban);
        assert_eq!(via_frontend.project.kind, direct.project.kind);
        assert_eq!(via_frontend.sources.len(), direct.sources.len());
        assert_eq!(
            via_frontend.project.source_files,
            direct.project.source_files
        );
    }
}
