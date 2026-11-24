//! Corpus licensing and provenance policy (docs/corpus-provenance.md).
//!
//! Every entry under `fixtures/third-party/` must have a `PROVENANCE.toml`
//! with a compatible license, a source URL, and an expected-findings manifest.

use std::path::{Component, Path, PathBuf};

const ALLOWED_LICENSES: &[&str] = &[
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unlicense",
    "CC0-1.0",
];

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn str_field<'a>(table: &'a toml::Table, key: &str) -> Result<&'a str, String> {
    match table.get(key).and_then(|v| v.as_str()).map(str::trim) {
        Some(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("missing `{key}`")),
    }
}

/// Validate one entry directory; returns every policy violation found.
fn check_entry(dir: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(dir.join("PROVENANCE.toml")) else {
        return vec!["missing PROVENANCE.toml".into()];
    };
    let table: toml::Table = match text.parse() {
        Ok(t) => t,
        Err(e) => return vec![format!("invalid PROVENANCE.toml: {e}")],
    };
    let mut errors = Vec::new();

    match str_field(&table, "license") {
        Ok(l) if ALLOWED_LICENSES.contains(&l) => {}
        Ok(l) => errors.push(format!("incompatible license `{l}`")),
        Err(e) => errors.push(e),
    }
    match str_field(&table, "source_url") {
        Ok(u) if u.starts_with("https://") && u.len() > "https://".len() => {}
        Ok(u) => errors.push(format!("`source_url` must be an https URL, got `{u}`")),
        Err(e) => errors.push(e),
    }
    match str_field(&table, "expected_findings") {
        Ok(p) => {
            let rel = Path::new(p);
            if rel.is_absolute() || rel.components().any(|c| matches!(c, Component::ParentDir)) {
                errors.push(format!(
                    "`expected_findings` must stay inside the entry: `{p}`"
                ));
            } else if !dir.join(rel).is_file() {
                errors.push(format!("expected-findings manifest `{p}` does not exist"));
            }
        }
        Err(e) => errors.push(e),
    }
    errors
}

#[test]
fn third_party_entries_have_valid_provenance() {
    let base = fixtures_dir().join("third-party");
    if !base.exists() {
        return;
    }
    let mut failures = Vec::new();
    let entries = match std::fs::read_dir(&base) {
        Ok(entries) => entries,
        Err(e) => panic!("cannot read third-party fixtures dir: {e}"),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            for err in check_entry(&path) {
                failures.push(format!("{}: {err}", path.display()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "provenance policy violations:\n{}",
        failures.join("\n")
    );
}

#[test]
fn valid_provenance_fixture_passes() {
    let valid_dir = fixtures_dir().join("provenance-checks/valid");
    let errors = check_entry(&valid_dir);
    assert!(
        errors.is_empty(),
        "expected valid fixture to pass: {errors:?}"
    );
}

#[test]
fn missing_provenance_is_rejected() {
    let dir = fixtures_dir().join("provenance-checks");
    let errors = check_entry(&dir);
    assert_eq!(errors, vec!["missing PROVENANCE.toml".to_string()]);
}

#[test]
fn invalid_provenance_fixtures_are_rejected() {
    let cases = [
        ("missing-license", "missing `license`"),
        ("incompatible-license", "incompatible license"),
        ("missing-source-url", "missing `source_url`"),
        ("missing-manifest", "missing `expected_findings`"),
        ("missing-file", "does not exist"),
    ];
    for (name, expected_err) in cases {
        let dir = fixtures_dir().join("provenance-checks").join(name);
        let errors = check_entry(&dir);
        assert!(
            errors.iter().any(|e| e.contains(expected_err)),
            "{name}: expected error containing `{expected_err}`, got {errors:?}"
        );
    }
}

#[test]
fn entry_without_provenance_file_is_rejected() {
    let dir = fixtures_dir().join("provenance-checks");
    assert_eq!(
        check_entry(&dir),
        vec!["missing PROVENANCE.toml".to_string()]
    );
}
