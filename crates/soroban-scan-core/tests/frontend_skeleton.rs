//! Compiling skeleton for `docs/contributors/adding-a-frontend.md`.
//!
//! The methods delegate to the Rust parser so this example stays small. A real
//! frontend replaces the delegation with its own discovery and item extraction.

use std::path::{Path, PathBuf};

use soroban_scan_core::discovery::{self, Discovered, DiscoveryOptions};
use soroban_scan_core::error::ScanError;
use soroban_scan_core::frontend::{Frontend, LoadedProject};
use soroban_scan_core::project;

/// A placeholder for a new language frontend.
struct ExampleFrontend;

impl Frontend for ExampleFrontend {
    fn name(&self) -> &'static str {
        "example"
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

#[test]
fn skeleton_implements_the_frontend_contract() {
    let frontend: &dyn Frontend = &ExampleFrontend;
    assert_eq!(frontend.name(), "example");

    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/projects/generic-rust");
    let discovered = frontend
        .discover(&root, &DiscoveryOptions::default())
        .expect("the skeleton discovers the fixture");
    assert_eq!(discovered.manifests.len(), 1);
}
