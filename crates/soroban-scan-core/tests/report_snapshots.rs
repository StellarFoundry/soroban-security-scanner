//! Golden snapshots for the machine-readable reports (#66).
//!
//! The whole regression corpus is scanned once and the JSON and SARIF renderings
//! are compared byte-for-byte with committed golden files. This makes any
//! unintended change to a machine format visible in review instead of being
//! caught piecemeal by unrelated assertions.
//!
//! Update procedure:
//!
//! ```text
//! UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test report_snapshots
//! ```
//!
//! On PowerShell:
//!
//! ```text
//! $env:UPDATE_SNAPSHOTS="1"; cargo test -p soroban-scan-core --test report_snapshots
//! ```
//!
//! Review the diff under `crates/soroban-scan-core/tests/snapshots/` before
//! committing it. The project root is normalized to `fixtures/corpus` and the
//! corpus contains no absolute paths, timestamps, or timings, so the snapshots
//! are reproducible across machines.

use std::path::{Path, PathBuf};

use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine::{self, ScanOutcome};
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::report;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn snapshot_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots")
}

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
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    walk(root, &mut files);
    files
}

fn relative_label(corpus: &Path, path: &Path) -> String {
    path.strip_prefix(corpus)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Scans every corpus source with a relative label.
///
/// Each file is scanned in memory with a stable relative name (for example
/// `SS-001/positive.rs`), then the outcomes are merged. Scanning this way keeps
/// paths, evidence and diagnostics relative and reproducible on every machine;
/// scanning the directory directly would embed the checkout's absolute path in
/// diagnostics and rule evidence.
fn corpus_outcome() -> ScanOutcome {
    let corpus = repo_root().join("fixtures/corpus");
    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let mut outcomes = Vec::new();

    for path in corpus_files(&corpus) {
        let label = relative_label(&corpus, &path);
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        outcomes.push(engine::scan_source_str(
            &content, &label, &config, &registry,
        ));
    }

    assert!(
        !outcomes.is_empty(),
        "the regression corpus must not be empty"
    );
    let labels = vec![String::new(); outcomes.len()];
    let mut merged = engine::merge(outcomes, &labels);
    merged.project.root = PathBuf::from("fixtures/corpus");
    merged
}

fn first_mismatch(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();
    for (index, (expected_line, actual_line)) in
        expected_lines.iter().zip(actual_lines.iter()).enumerate()
    {
        if expected_line != actual_line {
            return format!(
                "first difference at line {}:\n  expected: {expected_line}\n  actual:   {actual_line}",
                index + 1
            );
        }
    }
    format!(
        "line counts differ: expected {} line(s), actual {} line(s)",
        expected_lines.len(),
        actual_lines.len()
    )
}

fn assert_golden(name: &str, actual: &str) {
    let path = snapshot_dir().join(name);
    let actual = actual.replace("\r\n", "\n");

    if std::env::var("UPDATE_SNAPSHOTS").as_deref() == Ok("1") {
        std::fs::create_dir_all(snapshot_dir()).expect("create snapshot directory");
        std::fs::write(&path, actual.as_bytes())
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "missing golden snapshot {}: {error}\n\
             Generate it with UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test report_snapshots",
            path.display()
        )
    });
    let expected = expected.replace("\r\n", "\n");

    assert!(
        expected == actual,
        "{} changed: {}\n\
         Review the report change, then update the snapshot with \
         UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test report_snapshots",
        path.display(),
        first_mismatch(&expected, &actual)
    );
}

#[test]
fn json_report_matches_golden_snapshot() {
    let outcome = corpus_outcome();
    let json = report::render_json(&outcome).expect("JSON report must render");
    assert_golden("corpus.json", &json);
}

#[test]
fn sarif_report_matches_golden_snapshot() {
    let outcome = corpus_outcome();
    let registry = RuleRegistry::with_default_rules();
    let sarif = report::render_sarif(&outcome, &registry);
    assert_golden("corpus.sarif", &sarif);
}

#[test]
fn corpus_reports_are_deterministic() {
    let first = corpus_outcome();
    let second = corpus_outcome();

    assert_eq!(
        report::render_json(&first).unwrap(),
        report::render_json(&second).unwrap(),
        "JSON output must be byte-identical across runs"
    );

    let registry = RuleRegistry::with_default_rules();
    assert_eq!(
        report::render_sarif(&first, &registry),
        report::render_sarif(&second, &registry),
        "SARIF output must be byte-identical across runs"
    );
}
