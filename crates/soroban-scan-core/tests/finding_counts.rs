//! Per-rule finding counts over the regression corpus (#141).
//!
//! The whole regression corpus is scanned once and the number of findings per
//! rule is compared with a committed snapshot. The corpus test already proves
//! that each positive fixture triggers and each negative fixture does not; this
//! snapshot additionally pins *how many* findings each rule reports. A refactor
//! that silently broadens or narrows matching therefore fails here instead of
//! slipping through.
//!
//! Update procedure (only when the count change is intentional):
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test finding_counts
//! ```
//!
//! On PowerShell:
//!
//! ```text
//! $env:UPDATE_SNAPSHOTS="1"; cargo test -p soroban-scan-core --test finding_counts
//! ```
//!
//! Review the diff under `crates/soroban-scan-core/tests/snapshots/` and explain
//! the new or removed findings in the pull request. Never regenerate the
//! snapshot just to make an unrelated test pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn snapshot_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots/finding_counts.toml")
}

/// Collects every corpus fixture, sorted for deterministic output.
fn corpus_files(root: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, files);
            } else if path
                .extension()
                .is_some_and(|ext| ext == "rs" || ext == "toml")
            {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    walk(root, &mut files);
    files
}

/// Counts findings per rule id across the regression corpus.
///
/// Every registered rule starts at zero so a rule that stops reporting is
/// visible as a count drop rather than a missing key.
fn finding_counts() -> BTreeMap<String, usize> {
    let corpus = repo_root().join("fixtures/corpus");
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let mut counts: BTreeMap<String, usize> = registry
        .metadata_sorted()
        .iter()
        .map(|meta| (meta.id.to_string(), 0))
        .collect();

    let mut scanned = 0;
    for path in corpus_files(&corpus) {
        let label = path
            .strip_prefix(&corpus)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let outcome = if path.extension().is_some_and(|ext| ext == "toml") {
            engine::scan_manifest_str(&label, &content, &config, &registry)
                .unwrap_or_else(|error| panic!("{}: manifest fixture failed: {error}", label))
        } else {
            engine::scan_source_str(&content, &label, &config, &registry)
        };
        for finding in outcome.findings {
            *counts.entry(finding.rule_id).or_insert(0) += 1;
        }
        scanned += 1;
    }

    assert!(scanned > 0, "the regression corpus must not be empty");
    counts
}

fn render(counts: &BTreeMap<String, usize>) -> String {
    let mut text = String::from(
        "# Per-rule finding counts over fixtures/corpus (#141).\n\
         #\n\
         # Compared on every test run. Regenerate deliberately with:\n\
         #   UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test finding_counts\n\
         # and justify the count change in the pull request.\n\
         \n\
         [counts]\n",
    );
    for (id, count) in counts {
        text.push_str(&format!("{id} = {count}\n"));
    }
    text
}

#[test]
fn corpus_finding_counts_match_snapshot() {
    let actual = render(&finding_counts());
    let path = snapshot_path();

    if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().expect("snapshot directory"))
            .expect("create snapshot directory");
        std::fs::write(&path, actual.as_bytes())
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing finding-count snapshot {}: {error}\n\
             Generate it with UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test finding_counts",
            path.display()
        )
    });
    let expected = expected.replace("\r\n", "\n");

    if expected != actual {
        let expected_counts: BTreeMap<String, usize> = toml::from_str::<Snapshot>(&expected)
            .expect("snapshot must be valid TOML")
            .counts;
        let actual_counts = finding_counts();
        let mut details = Vec::new();
        for (id, actual_count) in &actual_counts {
            let expected_count = expected_counts.get(id).copied().unwrap_or(0);
            if expected_count != *actual_count {
                details.push(format!(
                    "{id}: expected {expected_count} finding(s), got {actual_count}"
                ));
            }
        }
        for (id, expected_count) in &expected_counts {
            if !actual_counts.contains_key(id) {
                details.push(format!(
                    "{id}: expected {expected_count} finding(s), got 0 (rule no longer registered)"
                ));
            }
        }
        panic!(
            "per-rule finding counts changed:\n{}\n\
             If the change is intentional, regenerate with \
             UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test finding_counts \
             and justify it in the pull request.",
            details.join("\n")
        );
    }
}

#[derive(serde::Deserialize)]
struct Snapshot {
    counts: BTreeMap<String, usize>,
}
