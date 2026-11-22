//! Black-box tests for the policy-driven status gate (#341).
//!
//! `fixtures/corpus/SS-001` contains two `high` SS-001 findings and nothing
//! `critical`, which makes `high` a failing threshold and `critical` a passing
//! one.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_soroban-scan"))
}

fn fixture(relative: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
        .to_string_lossy()
        .into_owned()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "soroban-scan-status-gate-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct Run {
    code: i32,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    let output = Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run soroban-scan");
    Run {
        code: output.status.code().unwrap_or(-1),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn read_gate(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path).expect("status gate file is written");
    serde_json::from_str(&text).expect("status gate is JSON")
}

fn scan_with_gate(dir: &Path, extra: &[&str]) -> (Run, serde_json::Value) {
    let gate = dir.join("gate.json");
    let corpus = fixture("corpus/SS-001");
    let gate_arg = gate.to_string_lossy().into_owned();
    let mut args = vec!["scan", corpus.as_str(), "--format", "json", "--no-config"];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--status-gate", gate_arg.as_str()]);
    let result = run(&args);
    let value = read_gate(&gate);
    (result, value)
}

#[test]
fn failing_policy_produces_a_failure_conclusion() {
    let dir = temp_dir("fail");
    let (result, gate) = scan_with_gate(&dir, &["--fail-on", "high"]);
    assert_eq!(result.code, 1, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "failure");
    assert_eq!(gate["threshold"], "high");
    assert_eq!(gate["blocking"], 2);
    assert!(gate["title"]
        .as_str()
        .unwrap()
        .contains("2 finding(s) at or above `high`"));
    assert!(result.stderr.contains("status gate: failure"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn passing_policy_produces_a_success_conclusion() {
    let dir = temp_dir("pass");
    let (result, gate) = scan_with_gate(&dir, &["--fail-on", "critical"]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "success");
    assert_eq!(gate["blocking"], 0);
    assert!(gate["gated"].as_u64().unwrap() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn disabled_policy_produces_a_neutral_conclusion() {
    let dir = temp_dir("neutral");
    let (result, gate) = scan_with_gate(&dir, &["--fail-on", "none"]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "neutral");
    assert_eq!(gate["threshold"], "none");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_policy_file_decides_the_conclusion() {
    let dir = temp_dir("policy");
    let policy = dir.join("policy.toml");
    let policy_arg = policy.to_string_lossy().into_owned();

    std::fs::write(&policy, "schema_version = 1\nfail_on = \"high\"\n").unwrap();
    let (result, gate) = scan_with_gate(&dir, &["--policy-file", policy_arg.as_str()]);
    assert_eq!(result.code, 1, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "failure");

    std::fs::write(&policy, "schema_version = 1\nfail_on = \"critical\"\n").unwrap();
    let (result, gate) = scan_with_gate(&dir, &["--policy-file", policy_arg.as_str()]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "success");

    std::fs::write(&policy, "schema_version = 1\nfail_on = \"none\"\n").unwrap();
    let (result, gate) = scan_with_gate(&dir, &["--policy-file", policy_arg.as_str()]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "neutral");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn suppressed_findings_do_not_fail_the_gate() {
    let dir = temp_dir("suppressed");
    let policy = dir.join("policy.toml");
    let policy_arg = policy.to_string_lossy().into_owned();
    std::fs::write(
        &policy,
        "schema_version = 1\nfail_on = \"high\"\n\n[[suppressions]]\npath = \"**\"\nrule = \"SS-001\"\nreason = \"accepted for this test\"\n",
    )
    .unwrap();
    let (result, gate) = scan_with_gate(&dir, &["--policy-file", policy_arg.as_str()]);
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "success");
    assert_eq!(gate["blocking"], 0);
    assert!(gate["suppressed"].as_u64().unwrap() >= 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn baseline_findings_do_not_fail_the_gate() {
    let dir = temp_dir("baseline");
    let baseline = dir.join("baseline.json");
    let baseline_arg = baseline.to_string_lossy().into_owned();
    let corpus = fixture("corpus/SS-001");
    let write = run(&[
        "scan",
        corpus.as_str(),
        "--no-config",
        "--write-baseline",
        baseline_arg.as_str(),
        "--quiet",
    ]);
    assert_eq!(write.code, 0, "{}", write.stderr);

    let (result, gate) = scan_with_gate(
        &dir,
        &["--fail-on", "high", "--baseline", baseline_arg.as_str()],
    );
    assert_eq!(result.code, 0, "{}", result.stderr);
    assert_eq!(gate["conclusion"], "success");
    assert_eq!(gate["gated"], 0);
    assert!(gate["baseline_accepted"].as_u64().unwrap() >= 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn summary_links_to_the_report_artifact() {
    let dir = temp_dir("url");
    let url = "https://github.com/owner/repo/actions/runs/1";
    let (result, gate) = scan_with_gate(&dir, &["--fail-on", "high", "--report-url", url]);
    assert_eq!(result.code, 1, "{}", result.stderr);
    assert_eq!(gate["report_url"], url);
    assert!(gate["summary"]
        .as_str()
        .unwrap()
        .contains(&format!("[Full scan report]({url})")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsafe_report_urls_are_usage_errors() {
    let dir = temp_dir("bad-url");
    let gate = dir.join("gate.json");
    let gate_arg = gate.to_string_lossy().into_owned();
    let corpus = fixture("corpus/SS-001");
    for url in [
        "javascript:alert(1)",
        "https://user:token@example.com/report",
        "https://example.com/a b",
    ] {
        let result = run(&[
            "scan",
            corpus.as_str(),
            "--no-config",
            "--status-gate",
            gate_arg.as_str(),
            "--report-url",
            url,
        ]);
        assert_eq!(result.code, 2, "{url}: {}", result.stderr);
        assert!(result.stderr.contains("--report-url"), "{}", result.stderr);
        assert!(!gate.exists(), "no gate is written for a rejected URL");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn report_url_requires_status_gate() {
    let corpus = fixture("corpus/SS-001");
    let result = run(&[
        "scan",
        corpus.as_str(),
        "--no-config",
        "--report-url",
        "https://example.com/report",
    ]);
    assert_eq!(result.code, 2, "{}", result.stderr);
}

#[test]
fn without_the_flag_no_gate_is_written() {
    let dir = temp_dir("off");
    let corpus = fixture("corpus/SS-001");
    let result = run(&["scan", corpus.as_str(), "--no-config", "--fail-on", "high"]);
    assert_eq!(result.code, 1);
    assert!(!result.stderr.contains("status gate:"));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}
