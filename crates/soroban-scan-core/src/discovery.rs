//! Deterministic filesystem discovery for Rust/Soroban projects.
//!
//! Discovery treats the filesystem as untrusted:
//! * symlinks are not followed by default,
//! * well-known build/vendor directories are skipped,
//! * user-supplied exclude globs are applied,
//! * results are sorted for deterministic ordering.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};
use walkdir::WalkDir;

use crate::error::ScanError;

/// Directory names that are always skipped during discovery.
pub const DEFAULT_IGNORED_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "target",
    "node_modules",
    "vendor",
    ".scanner-cache",
    ".cargo",
];

/// Options controlling discovery behavior.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryOptions {
    /// Whether to follow symbolic links. Defaults to `false`.
    pub follow_symlinks: bool,
    /// Glob patterns (relative to the scan root) to exclude.
    pub exclude: Vec<String>,
    /// Skip test directories (any directory named `tests`).
    pub exclude_tests: bool,
    /// Keep items gated behind `#[cfg(test)]` instead of skipping them.
    /// Defaults to `false`: cfg(test) items are skipped.
    pub include_cfg_test: bool,
    /// Exclude source files marked as generated instead of marking them.
    pub exclude_generated: bool,
}

/// Files discovered during a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovered {
    /// Paths to `Cargo.toml` manifests.
    pub manifests: Vec<PathBuf>,
    /// Paths to Rust source files.
    pub rust_files: Vec<PathBuf>,
}

/// Compiles exclude patterns into a [`GlobSet`].
pub fn compile_excludes(patterns: &[String]) -> Result<GlobSet, ScanError> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .map_err(|e| ScanError::Config(format!("invalid exclude glob '{pattern}': {e}")))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|e| ScanError::Config(format!("invalid exclude globs: {e}")))
}

fn is_ignored_dir(name: &str, exclude_tests: bool) -> bool {
    DEFAULT_IGNORED_DIRS.contains(&name) || (exclude_tests && name == "tests")
}

fn to_slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn is_excluded(root: &Path, path: &Path, excludes: &GlobSet) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path);
    excludes.is_match(to_slash(rel))
}

/// Discovers manifests and Rust source files under `root`.
pub fn discover(root: &Path, opts: &DiscoveryOptions) -> Result<Discovered, ScanError> {
    if !root.exists() {
        return Err(ScanError::io(
            root,
            std::io::Error::new(std::io::ErrorKind::NotFound, "scan root does not exist"),
        ));
    }

    let excludes = compile_excludes(&opts.exclude)?;
    let mut discovered = Discovered::default();

    let walker = WalkDir::new(root)
        .follow_links(opts.follow_symlinks)
        .sort_by_file_name();

    for entry in walker.into_iter().filter_entry(|e| {
        // Prune ignored directories, but never prune the root itself.
        if e.file_type().is_dir() {
            match e.file_name().to_str() {
                Some(name) => !is_ignored_dir(name, opts.exclude_tests),
                None => true,
            }
        } else {
            true
        }
    }) {
        let entry = match entry {
            Ok(e) => e,
            // A single unreadable entry must not abort the whole scan.
            Err(_) => continue,
        };

        let path = entry.path();
        if path == root {
            continue;
        }

        if entry.file_type().is_symlink() && !opts.follow_symlinks {
            continue;
        }

        if is_excluded(root, path, &excludes) {
            continue;
        }

        if entry.file_type().is_dir() {
            continue;
        }

        match path.file_name().and_then(|n| n.to_str()) {
            Some("Cargo.toml") => discovered.manifests.push(path.to_path_buf()),
            Some(name) if name.ends_with(".rs") => discovered.rust_files.push(path.to_path_buf()),
            _ => {}
        }
    }

    discovered.manifests.sort();
    discovered.rust_files.sort();
    Ok(discovered)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "soroban-scan-discover-{}-{}",
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
    fn discovers_manifests_and_sources() {
        let root = tmpdir("basic");
        write(&root.join("Cargo.toml"), "[package]\nname='a'\n");
        write(&root.join("src/lib.rs"), "fn main() {}");
        write(
            &root.join("contracts/c/Cargo.toml"),
            "[package]\nname='c'\n",
        );
        write(&root.join("contracts/c/src/lib.rs"), "fn f() {}");
        write(&root.join("contracts/c/README.md"), "docs");

        let found = discover(&root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(found.manifests.len(), 2);
        assert_eq!(found.rust_files.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn skips_target_directory() {
        let root = tmpdir("target");
        write(&root.join("Cargo.toml"), "[package]\nname='a'\n");
        write(&root.join("src/lib.rs"), "fn f() {}");
        write(&root.join("target/debug/build.rs"), "fn g() {}");

        let found = discover(&root, &DiscoveryOptions::default()).unwrap();
        assert_eq!(found.rust_files.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn applies_exclude_globs() {
        let root = tmpdir("exclude");
        write(&root.join("Cargo.toml"), "[package]\nname='a'\n");
        write(&root.join("src/lib.rs"), "fn f() {}");
        write(&root.join("tests/it.rs"), "fn t() {}");

        let opts = DiscoveryOptions {
            follow_symlinks: false,
            exclude: vec!["tests/**".to_string()],
            exclude_tests: false,
            include_cfg_test: false,
            exclude_generated: false,
        };
        let found = discover(&root, &opts).unwrap();
        assert_eq!(found.rust_files.len(), 1);
        assert!(found.rust_files[0].ends_with("lib.rs"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exclude_tests_prunes_test_directories() {
        let root = tmpdir("exclude-tests");
        write(&root.join("Cargo.toml"), "[package]\nname='a'\n");
        write(&root.join("src/lib.rs"), "fn f() {}");
        write(&root.join("tests/integration.rs"), "fn t() {}");
        write(&root.join("crates/c/tests/helper.rs"), "fn h() {}");

        let opts = DiscoveryOptions {
            exclude_tests: true,
            ..DiscoveryOptions::default()
        };
        let found = discover(&root, &opts).unwrap();
        assert_eq!(found.rust_files.len(), 1);
        assert!(found.rust_files[0].ends_with("lib.rs"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_invalid_exclude_glob() {
        let root = tmpdir("badglob");
        let opts = DiscoveryOptions {
            follow_symlinks: false,
            exclude: vec!["[".to_string()],
            exclude_tests: false,
            include_cfg_test: false,
            exclude_generated: false,
        };
        assert!(matches!(discover(&root, &opts), Err(ScanError::Config(_))));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn errors_on_missing_root() {
        let missing = std::env::temp_dir().join("soroban-scan-does-not-exist-xyz");
        let _ = std::fs::remove_dir_all(&missing);
        assert!(discover(&missing, &DiscoveryOptions::default()).is_err());
    }
}
