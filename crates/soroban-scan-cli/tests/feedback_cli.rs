//! Black-box tests for the offline false-positive feedback command (#303).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_DIR: AtomicUsize = AtomicUsize::new(0);

const FINGERPRINT: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
const OTHER_FINGERPRINT: &str = "ffffffffffffffffffffffffffffffff";

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

fn temp_dir(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "soroban-feedback-cli-{}-{}-{}",
        std::process::id(),
        name,
        NEXT_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

fn store_path(dir: &Path) -> PathBuf {
    dir.join("feedback.json")
}

#[test]
fn records_feedback_offline_and_deduplicates() {
    let dir = temp_dir("record");
    let dir_arg = dir.to_str().unwrap();

    let first = run(&[
        "feedback",
        "--rule",
        "SS-001",
        "--span-hash",
        FINGERPRINT,
        "--reason",
        "reviewed as intended behavior",
        "--dir",
        dir_arg,
    ]);
    assert_eq!(first.code, 0, "stderr: {}", first.stderr);
    assert!(first.stdout.contains("recorded false-positive feedback"));

    let path = store_path(&dir);
    let text = std::fs::read_to_string(&path).expect("read feedback store");
    let value: serde_json::Value = serde_json::from_str(&text).expect("parse feedback store");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["tool"], "soroban-scan");
    assert_eq!(value["entries"].as_array().unwrap().len(), 1);
    assert_eq!(value["entries"][0]["rule_id"], "SS-001");
    assert_eq!(value["entries"][0]["fingerprint"], FINGERPRINT);
    assert_eq!(
        value["entries"][0]["reason"],
        "reviewed as intended behavior"
    );

    let second = run(&[
        "feedback",
        "--rule",
        "SS-001",
        "--span-hash",
        FINGERPRINT,
        "--reason",
        "reviewed as intended behavior",
        "--dir",
        dir_arg,
    ]);
    assert_eq!(second.code, 0, "stderr: {}", second.stderr);
    assert!(second.stdout.contains("already recorded"));
    let value: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(value["entries"].as_array().unwrap().len(), 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn redacts_reason_and_never_copies_source_text() {
    let dir = temp_dir("redaction");
    let dir_arg = dir.to_str().unwrap();
    let source = dir.join("source.rs");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(&source, "let distinctive_source_token = 42;").unwrap();

    let result = run(&[
        "feedback",
        "--rule",
        "SS-001",
        "--fingerprint",
        FINGERPRINT,
        "--reason",
        "api_key = sk-live-super-secret-token",
        "--dir",
        dir_arg,
    ]);
    assert_eq!(result.code, 0, "stderr: {}", result.stderr);

    let text = std::fs::read_to_string(store_path(&dir)).unwrap();
    assert!(!text.contains("sk-live-super-secret-token"));
    assert!(!text.contains("distinctive_source_token"));
    assert!(!text.contains("source.rs"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn entries_are_sorted_independently_of_insertion_order() {
    let first_dir = temp_dir("order-a");
    let second_dir = temp_dir("order-b");

    for (dir, first, second) in [
        (
            &first_dir,
            ("SS-002", OTHER_FINGERPRINT),
            ("SS-001", FINGERPRINT),
        ),
        (
            &second_dir,
            ("SS-001", FINGERPRINT),
            ("SS-002", OTHER_FINGERPRINT),
        ),
    ] {
        let dir_arg = dir.to_str().unwrap();
        for (rule, hash) in [first, second] {
            let result = run(&[
                "feedback",
                "--rule",
                rule,
                "--span-hash",
                hash,
                "--dir",
                dir_arg,
            ]);
            assert_eq!(result.code, 0, "stderr: {}", result.stderr);
        }
    }

    let first = std::fs::read_to_string(store_path(&first_dir)).unwrap();
    let second = std::fs::read_to_string(store_path(&second_dir)).unwrap();
    assert_eq!(first, second);

    let _ = std::fs::remove_dir_all(&first_dir);
    let _ = std::fs::remove_dir_all(&second_dir);
}

#[test]
fn invalid_arguments_are_usage_errors() {
    let dir = temp_dir("invalid");
    let dir_arg = dir.to_str().unwrap();

    for args in [
        vec![
            "feedback",
            "--rule",
            "SS-999",
            "--span-hash",
            FINGERPRINT,
            "--dir",
            dir_arg,
        ],
        vec![
            "feedback",
            "--rule",
            "SS-001",
            "--span-hash",
            "not-a-hash",
            "--dir",
            dir_arg,
        ],
        vec![
            "feedback",
            "--rule",
            "SS-001",
            "--span-hash",
            FINGERPRINT,
            "--reason",
            &"x".repeat(600),
            "--dir",
            dir_arg,
        ],
    ] {
        let result = run(&args);
        assert_eq!(result.code, 2, "stderr: {}", result.stderr);
    }
    assert!(!store_path(&dir).exists());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn malformed_store_is_a_runtime_error() {
    let dir = temp_dir("malformed");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(store_path(&dir), "{").unwrap();

    let result = run(&[
        "feedback",
        "--rule",
        "SS-001",
        "--span-hash",
        FINGERPRINT,
        "--dir",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(result.code, 3, "stderr: {}", result.stderr);
    assert!(result.stderr.contains("failed to parse feedback.json"));

    let _ = std::fs::remove_dir_all(&dir);
}
