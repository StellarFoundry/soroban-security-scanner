//! Black-box tests for monorepo path filtering (#343).
//!
//! `fixtures/projects/monorepo` holds a root workspace, a nested `contracts`
//! workspace with two members (one of which contains another crate), and a
//! tool crate. Each project's `src/lib.rs` has exactly one SS-001 trigger, so
//! the set of files with SS-001 findings is the set of projects scanned.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;

const TOKEN: &str = "contracts/token/src/lib.rs";
const VAULT: &str = "contracts/vault/src/lib.rs";
const ADAPTER: &str = "contracts/vault/adapter/src/lib.rs";
const GEN: &str = "tools/gen/src/lib.rs";

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_soroban-scan"))
}

fn monorepo() -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/projects/monorepo")
        .to_string_lossy()
        .into_owned()
}

fn temp_file(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "soroban-scan-monorepo-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("changed.txt");
    std::fs::write(&path, contents).unwrap();
    path
}

struct Scan {
    code: i32,
    stderr: String,
    files: BTreeSet<String>,
}

fn scan(extra: &[&str]) -> Scan {
    let root = monorepo();
    let mut args = vec![
        "scan",
        root.as_str(),
        "--format",
        "json",
        "--no-config",
        "--fail-on",
        "none",
        "--rule",
        "SS-001",
    ];
    args.extend_from_slice(extra);
    let output = Command::new(bin())
        .args(&args)
        .output()
        .expect("failed to run soroban-scan");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    let files = if code == 0 {
        let report: serde_json::Value =
            serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("{e}: {stdout}\n{stderr}"));
        report["findings"]
            .as_array()
            .expect("findings array")
            .iter()
            .map(|finding| {
                finding["location"]["file"]
                    .as_str()
                    .unwrap()
                    .replace('\\', "/")
            })
            .collect()
    } else {
        BTreeSet::new()
    };
    Scan {
        code,
        stderr,
        files,
    }
}

fn set(files: &[&str]) -> BTreeSet<String> {
    files.iter().map(|file| file.to_string()).collect()
}

#[test]
fn without_filters_every_project_is_scanned() {
    let result = scan(&[]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.files, set(&[TOKEN, VAULT, ADAPTER, GEN]));
    assert!(!result.stderr.contains("effective scope"));
}

#[test]
fn include_selects_a_nested_workspace_and_its_members() {
    let result = scan(&["--include-project", "contracts"]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.files, set(&[TOKEN, VAULT, ADAPTER]));
    assert!(
        result
            .stderr
            .contains("effective scope: 1 of 6 project(s): contracts"),
        "{}",
        result.stderr
    );
    assert!(result.stderr.contains("skipped tools/gen (not included)"));
}

#[test]
fn exclude_wins_and_is_inherited_by_nested_crates() {
    let result = scan(&[
        "--include-project",
        "contracts",
        "--exclude-project",
        "contracts/vault",
    ]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.files, set(&[TOKEN]));
    assert!(result.stderr.contains("skipped contracts/vault (excluded)"));
    assert!(result
        .stderr
        .contains("skipped contracts/vault/adapter (excluded)"));
}

#[test]
fn changed_files_select_the_owning_projects_only() {
    let list = temp_file(
        "changed",
        "contracts/vault/adapter/src/lib.rs\n./tools/gen/Cargo.toml\n",
    );
    let list = list.to_string_lossy().into_owned();
    let result = scan(&["--changed-files", list.as_str()]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.files, set(&[ADAPTER, GEN]));
    assert!(result
        .stderr
        .contains("skipped contracts/vault (unchanged)"));
}

#[test]
fn a_changed_member_excludes_its_unchanged_nested_crate() {
    let list = temp_file("member", "contracts/vault/src/lib.rs\n");
    let list = list.to_string_lossy().into_owned();
    let result = scan(&["--changed-files", list.as_str()]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.files, set(&[VAULT]));
}

#[test]
fn filters_combine() {
    let list = temp_file(
        "combined",
        "contracts/token/src/lib.rs\ntools/gen/src/lib.rs\n",
    );
    let list = list.to_string_lossy().into_owned();
    let result = scan(&[
        "--changed-files",
        list.as_str(),
        "--exclude-project",
        "tools/*",
    ]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.files, set(&[TOKEN]));
}

#[test]
fn nothing_changed_scans_nothing_and_says_so() {
    let list = temp_file("empty", "docs/notes.txt\n");
    let list = list.to_string_lossy().into_owned();
    let result = scan(&["--changed-files", list.as_str()]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    // docs/notes.txt is owned by the root workspace, which has no sources.
    assert!(result.files.is_empty());
    assert!(result
        .stderr
        .contains("effective scope: 1 of 6 project(s): ."));
}

#[test]
fn changed_files_outside_the_root_are_rejected() {
    for entry in ["../secrets.rs", "/etc/passwd", "contracts/../../x.rs"] {
        let list = temp_file("escape", &format!("{entry}\n"));
        let list = list.to_string_lossy().into_owned();
        let result = scan(&["--changed-files", list.as_str()]);
        assert_eq!(result.code, 2, "{entry}: {}", result.stderr);
        assert!(result.stderr.contains("changed file"), "{}", result.stderr);
    }
}

#[test]
fn project_globs_outside_the_root_are_rejected() {
    let result = scan(&["--include-project", "../elsewhere"]);
    assert_eq!(result.code, 2, "{}", result.stderr);
}

#[test]
fn quiet_hides_the_scope_but_keeps_the_filter() {
    let result = scan(&["--include-project", "tools/gen", "--quiet"]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(result.files, set(&[GEN]));
    assert!(!result.stderr.contains("effective scope"));
}

#[test]
fn filtering_requires_a_single_directory() {
    let root = monorepo();
    let file = format!("{root}/contracts/token/src/lib.rs");
    let output = Command::new(bin())
        .args([
            "scan",
            file.as_str(),
            "--no-config",
            "--include-project",
            "contracts",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));

    let output = Command::new(bin())
        .args([
            "scan",
            root.as_str(),
            root.as_str(),
            "--no-config",
            "--include-project",
            "contracts",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn changed_files_conflicts_with_files_from() {
    let list = temp_file("conflict", "contracts/token/src/lib.rs\n");
    let list = list.to_string_lossy().into_owned();
    let result = scan(&[
        "--changed-files",
        list.as_str(),
        "--files-from",
        list.as_str(),
    ]);
    assert_eq!(result.code, 2, "{}", result.stderr);
}
