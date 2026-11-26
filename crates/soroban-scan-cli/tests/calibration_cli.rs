//! Black-box tests for the deterministic calibration report command (#302).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(args: &[&str]) -> Output {
    let result = Command::new(env!("CARGO_BIN_EXE_soroban-scan"))
        .args(args)
        .output()
        .expect("run soroban-scan");
    Output {
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        code: result.status.code().unwrap_or(-1),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn committed_dir() -> PathBuf {
    repo_root().join("docs/rules/calibration")
}

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "soroban-calibration-cli-{}-{}-{}",
        std::process::id(),
        name,
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn assert_same_file(expected_path: &Path, actual_path: &Path) {
    let expected = std::fs::read_to_string(expected_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", expected_path.display()));
    let actual = std::fs::read_to_string(actual_path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", actual_path.display()));
    assert_eq!(
        expected.replace("\r\n", "\n"),
        actual.replace("\r\n", "\n"),
        "{} differs",
        actual_path.display()
    );
}

#[test]
fn calibration_json_is_deterministic_and_matches_committed_artifact() {
    let root = repo_root();
    let root_arg = root.to_str().unwrap();
    let first = run(&["calibrate", "--root", root_arg, "--format", "json"]);
    assert_eq!(first.code, 0, "stderr: {}", first.stderr);
    let second = run(&["calibrate", "--root", root_arg, "--format", "json"]);
    assert_eq!(second.code, 0, "stderr: {}", second.stderr);
    assert_eq!(first.stdout, second.stdout);

    let committed = std::fs::read_to_string(committed_dir().join("calibration.json"))
        .expect("read committed calibration JSON");
    assert_eq!(
        committed.replace("\r\n", "\n"),
        first.stdout.replace("\r\n", "\n")
    );

    let value: serde_json::Value =
        serde_json::from_str(&first.stdout).expect("parse calibration JSON");
    assert_eq!(value["schema_version"], "1");
    assert_eq!(value["tool"], "soroban-scan");
    assert_eq!(value["corpus"], "fixtures/corpus");
    assert_eq!(value["scope"], "built-in-defaults");
    let rules = value["rules"].as_array().expect("rules array");
    assert_eq!(rules.len(), 47);
    assert_eq!(value["totals"]["rules"], 47);
    assert!(!first.stdout.contains("runtime_micros"));
    assert!(!first.stdout.contains(root_arg));
}

#[test]
fn per_rule_reports_match_committed_artifacts() {
    let root = repo_root();
    let root_arg = root.to_str().unwrap();
    let out = temp_dir("rules");
    let out_arg = out.to_str().unwrap();
    let result = run(&[
        "calibrate",
        "--root",
        root_arg,
        "--format",
        "markdown",
        "--per-rule-dir",
        out_arg,
    ]);
    assert_eq!(result.code, 0, "stderr: {}", result.stderr);

    let committed = committed_dir();
    let mut generated: Vec<PathBuf> = std::fs::read_dir(&out)
        .expect("read generated reports")
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("md"))
        .collect();
    generated.sort();
    assert_eq!(generated.len(), 47);
    for path in generated {
        let name = path.file_name().expect("file name").to_string_lossy();
        assert_same_file(&committed.join(name.as_ref()), &path);
    }
    assert!(result.stdout.contains("Rule Calibration Report"));
    assert!(result.stdout.contains("Review candidates"));
}
