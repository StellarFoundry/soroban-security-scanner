//! Module paths follow `mod` declarations, `mod.rs`, and `#[path]` (#44).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use soroban_scan_core::discovery::DiscoveryOptions;
use soroban_scan_core::project;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/projects")
        .join(name)
}

#[test]
fn module_paths_follow_the_declared_module_tree() {
    let root = fixture("nested-modules");
    let loaded = project::load(&root, &DiscoveryOptions::default()).unwrap();

    let paths: BTreeMap<String, String> = loaded
        .sources
        .iter()
        .map(|source| {
            let relative = source
                .path
                .strip_prefix(&root)
                .unwrap_or(Path::new(""))
                .to_string_lossy()
                .replace('\\', "/");
            (relative, source.module_path.clone())
        })
        .collect();

    assert_eq!(paths["src/lib.rs"], "crate");
    assert_eq!(paths["src/alpha.rs"], "crate::alpha");
    assert_eq!(paths["src/alpha/beta/mod.rs"], "crate::alpha::beta");
    assert_eq!(
        paths["src/alpha/beta/gamma.rs"],
        "crate::alpha::beta::gamma"
    );
    assert_eq!(paths["src/alt/renamed.rs"], "crate::renamed");
    assert_eq!(paths["src/inline/nested.rs"], "crate::inline::nested");
}
