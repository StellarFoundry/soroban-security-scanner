//! Documented example contract corpus (#320).
//!
//! The examples are source-only: this test parses them and checks their
//! documentation. It never compiles, executes, deploys, or signs a contract.

use std::path::{Path, PathBuf};

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/contracts")
}

fn example_files() -> Vec<PathBuf> {
    let root = corpus_root();
    let mut files = Vec::new();
    for category in std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", root.display()))
        .filter_map(Result::ok)
    {
        if !category.path().is_dir() {
            continue;
        }
        for example in std::fs::read_dir(category.path())
            .unwrap_or_else(|error| panic!("cannot read category: {error}"))
            .filter_map(Result::ok)
        {
            let path = example.path();
            if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[test]
fn example_corpus_is_documented_and_parseable() {
    let files = example_files();
    assert!(
        files.len() >= 50,
        "expected at least 50 example contracts, found {}",
        files.len()
    );

    for path in files {
        let relative = path.strip_prefix(corpus_root()).unwrap_or(&path);
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        assert!(
            source.starts_with("// SPDX-License-Identifier: MIT\n"),
            "{}: missing MIT SPDX header",
            relative.display()
        );
        let category = path
            .parent()
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        assert!(
            source.contains(&format!("//! Category: {category}\n")),
            "{}: header category must match its directory {category:?}",
            relative.display()
        );
        assert!(
            source
                .lines()
                .any(|line| line.starts_with("//! Focus: ")
                    && line.trim().len() > "//! Focus:".len()),
            "{}: missing non-empty focus header",
            relative.display()
        );
        assert!(
            source.contains("#[contractimpl]"),
            "{}: not a contract example",
            relative.display()
        );
        syn::parse_file(&source)
            .unwrap_or_else(|error| panic!("{}: does not parse: {error}", relative.display()));
    }
}
