//! Black-box CLI integration tests.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_soroban-scan"))
}

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(relative)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

struct Output {
    stdout: String,
    stderr: String,
    code: i32,
}

fn run(args: &[&str]) -> Output {
    let result = Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run soroban-scan");
    Output {
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        code: result.status.code().unwrap_or(-1),
    }
}

fn run_with_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(bin());
    command.args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    let result = command.output().expect("failed to run soroban-scan");
    Output {
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        code: result.status.code().unwrap_or(-1),
    }
}

fn run_with_stdin(args: &[&str], input: &str) -> Output {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new(bin())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn soroban-scan");
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(input.as_bytes())
        .expect("failed to write to stdin");
    let result = child.wait_with_output().expect("failed to read output");
    Output {
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        code: result.status.code().unwrap_or(-1),
    }
}

fn run_in(dir: &Path, args: &[&str]) -> Output {
    let result = Command::new(bin())
        .current_dir(dir)
        .args(args)
        .output()
        .expect("failed to run soroban-scan");
    Output {
        stdout: String::from_utf8_lossy(&result.stdout).to_string(),
        stderr: String::from_utf8_lossy(&result.stderr).to_string(),
        code: result.status.code().unwrap_or(-1),
    }
}

#[test]
fn scan_piped_terminal_report_is_complete() {
    // A tiny threshold would page on a terminal, but stdout is a pipe here, so
    // the report must be written verbatim.
    let out = run_with_env(
        &[
            "scan",
            fixture("corpus/SS-001").to_str().unwrap(),
            "--quiet",
        ],
        &[("SOROBAN_SCAN_PAGE_THRESHOLD", "1")],
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("SS-001"));
}

#[test]
fn scan_pager_never_writes_the_whole_report() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--quiet",
        "--pager",
        "never",
    ]);
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("SS-001"));
}

#[test]
fn scan_json_is_never_paged() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--format",
        "json",
        "--fail-on",
        "none",
        "--pager",
        "always",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let _: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
}

#[test]
fn scan_stdin_uses_the_supplied_filename_for_locations() {
    let source = std::fs::read_to_string(fixture("corpus/SS-001/positive.rs")).unwrap();
    let out = run_with_stdin(
        &[
            "scan",
            "--stdin-filename",
            "src/lib.rs",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
        &source,
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let findings = value["findings"].as_array().unwrap();
    assert!(!findings.is_empty());
    assert_eq!(findings[0]["location"]["file"], "src/lib.rs");
}

#[test]
fn scan_stdin_respects_the_failure_gate() {
    let source = std::fs::read_to_string(fixture("corpus/SS-001/positive.rs")).unwrap();
    let out = run_with_stdin(
        &["scan", "--stdin-filename", "src/lib.rs", "--quiet"],
        &source,
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
    assert!(out.stdout.contains("SS-001"));
}

#[test]
fn scan_stdin_rejects_a_filename_escaping_the_root() {
    let out = run_with_stdin(&["scan", "--stdin-filename", "../escape.rs"], "fn f() {}");
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("escape"), "stderr: {}", out.stderr);
}

#[test]
fn scan_stdin_rejects_an_empty_filename() {
    let out = run_with_stdin(&["scan", "--stdin-filename", "   "], "fn f() {}");
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("empty"), "stderr: {}", out.stderr);
}

#[test]
fn scan_multiple_paths_merges_results_with_unambiguous_locations() {
    let out = run_in(
        &repo_root(),
        &[
            "scan",
            "fixtures/corpus/SS-001",
            "fixtures/corpus/SS-003",
            "--format",
            "json",
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let findings = value["findings"].as_array().unwrap();
    let files: Vec<&str> = findings
        .iter()
        .map(|f| f["location"]["file"].as_str().unwrap())
        .collect();
    assert!(files
        .iter()
        .any(|f| f.starts_with("fixtures/corpus/SS-001/")));
    assert!(files
        .iter()
        .any(|f| f.starts_with("fixtures/corpus/SS-003/")));
    let rules: Vec<&str> = findings
        .iter()
        .map(|f| f["rule_id"].as_str().unwrap())
        .collect();
    assert!(rules.contains(&"SS-001"));
    assert!(rules.contains(&"SS-003"));
}

#[test]
fn scan_multiple_paths_applies_the_failure_gate() {
    let out = run_in(
        &repo_root(),
        &[
            "scan",
            "fixtures/corpus/SS-001",
            "fixtures/corpus/SS-003",
            "--quiet",
        ],
    );
    assert_eq!(out.code, 1, "stderr: {}", out.stderr);
}

#[test]
fn scan_multiple_paths_rejects_paths_outside_the_working_directory() {
    let out = run_in(
        &repo_root(),
        &["scan", "fixtures/corpus/SS-001", "..", "--fail-on", "none"],
    );
    assert_eq!(out.code, 2);
    assert!(
        out.stderr.contains("inside the current directory"),
        "stderr: {}",
        out.stderr
    );
}

#[test]
fn version_exits_zero_and_prints_name() {
    let out = run(&["version"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("soroban-scan"));
    assert!(out.stdout.contains(soroban_scan_core::VERSION));
}

#[test]
fn rules_lists_built_in_rules() {
    let out = run(&["rules"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("SS-001"));
    assert!(out.stdout.contains("SS-007"));
}

#[test]
fn explain_known_rule_succeeds() {
    let out = run(&["explain", "SS-001"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("SS-001"));
    assert!(out.stdout.contains("Remediation"));
}

#[test]
fn explain_unknown_rule_is_usage_error() {
    let out = run(&["explain", "SS-999"]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("unknown rule id"));
}

#[test]
fn scan_positive_fixture_fails_the_gate() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--quiet",
    ]);
    assert_eq!(out.code, 1);
    assert!(out.stdout.contains("SS-001"));
}

#[test]
fn scan_with_fail_on_none_exits_zero() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--quiet",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0);
}

#[test]
fn scan_json_output_is_machine_readable() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--format",
        "json",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(value["tool"]["name"], "soroban-scan");
    assert!(!value["findings"].as_array().unwrap().is_empty());
}

#[test]
fn scan_json_includes_diagnostic_codes_and_levels() {
    let out = run(&[
        "scan",
        fixture("projects/parse-error").to_str().unwrap(),
        "--format",
        "json",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let diagnostics = value["diagnostics"].as_array().unwrap();
    assert!(!diagnostics.is_empty());
    assert_eq!(diagnostics[0]["code"], "PARSE-001");
    assert_eq!(diagnostics[0]["level"], "warning");
}

#[test]
fn scan_github_output_emits_workflow_annotations() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--format",
        "github",
        "--min-severity",
        "high",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let lines: Vec<_> = out.stdout.lines().collect();
    assert!(!lines.is_empty(), "expected at least one annotation");
    for line in lines {
        assert!(
            line.starts_with("::error file=") || line.starts_with("::warning "),
            "unexpected annotation: {line}"
        );
        assert!(line.contains("line="), "missing line property: {line}");
        assert!(line.contains("title=SS-001"), "missing title: {line}");
        assert!(line.contains("::SS-001:"), "missing message: {line}");
    }
}

#[test]
fn scan_sarif_output_is_valid() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--format",
        "sarif",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(value["version"], "2.1.0");
    assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "soroban-scan");
}

#[test]
fn scan_missing_path_is_runtime_error() {
    let out = run(&["scan", "definitely/not/a/real/path/xyz"]);
    assert_eq!(out.code, 3);
}

#[test]
fn init_creates_then_refuses_to_overwrite() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-init-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let first = run(&["init", dir.to_str().unwrap()]);
    assert_eq!(first.code, 0);
    assert!(dir.join("soroban-scan.toml").exists());

    let second = run(&["init", dir.to_str().unwrap()]);
    assert_eq!(second.code, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn baseline_suppresses_existing_findings() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-bl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let baseline = dir.join("baseline.json");

    let write = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--write-baseline",
        baseline.to_str().unwrap(),
        "--quiet",
    ]);
    assert_eq!(write.code, 0);
    assert!(baseline.exists());

    // Known findings no longer fail the high gate.
    let known = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
        "--fail-on",
        "high",
        "--quiet",
    ]);
    assert_eq!(known.code, 0);

    // new-only output is empty because everything is baselined.
    let new_only = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
        "--new-only",
        "--fail-on",
        "none",
        "--quiet",
    ]);
    assert_eq!(new_only.code, 0);
    assert!(new_only.stdout.contains("0 finding(s)"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn baseline_from_clean_project_flags_all_findings_as_new() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-bl2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let baseline = dir.join("baseline.json");

    let write = run(&[
        "scan",
        fixture("projects/soroban-confirmed").to_str().unwrap(),
        "--write-baseline",
        baseline.to_str().unwrap(),
        "--quiet",
    ]);
    assert_eq!(write.code, 0);

    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--baseline",
        baseline.to_str().unwrap(),
        "--fail-on",
        "high",
        "--quiet",
    ]);
    assert_eq!(out.code, 1);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn files_from_scans_only_listed_files() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-ff-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("changed.txt");
    std::fs::write(&list, "fixtures/corpus/SS-001/positive.rs\n").unwrap();

    let out = run(&[
        "scan",
        repo_root().to_str().unwrap(),
        "--files-from",
        list.to_str().unwrap(),
        "--quiet",
        "--fail-on",
        "high",
    ]);
    assert_eq!(out.code, 1);
    assert!(out.stdout.contains("positive.rs"));
    assert!(!out.stdout.contains("negative.rs"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rules_search_filters_results() {
    let out = run(&["rules", "--search", "ttl"]);
    assert_eq!(out.code, 0);
    assert!(out.stdout.contains("SS-006"));
    assert!(!out.stdout.contains("SS-001"));
}

#[test]
fn rules_unknown_category_is_usage_error() {
    let out = run(&["rules", "--category", "nonsense"]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("unknown category"));
}

#[test]
fn guidance_is_offline_and_labeled() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--fail-on",
        "none",
        "--quiet",
        "--guidance",
    ]);
    assert_eq!(out.code, 0);
    assert!(out.stderr.contains("GUIDANCE (offline, rule-based)"));
    assert!(out.stderr.contains("deterministic findings"));
}

#[test]
fn enabling_ai_without_a_provider_fails_closed() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-ai-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("ai.toml");
    std::fs::write(&config, "[ai]\nenabled = true\nprovider = \"openai\"\n").unwrap();

    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--fail-on",
        "none",
        "--quiet",
        "--guidance",
    ]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("assistance is unavailable"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn files_from_rejects_path_traversal() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-ff2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let list = dir.join("changed.txt");
    std::fs::write(&list, "../outside.rs\n").unwrap();

    let out = run(&[
        "scan",
        repo_root().to_str().unwrap(),
        "--files-from",
        list.to_str().unwrap(),
    ]);
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("escapes the scan root"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Writes a minimal Soroban project whose single entry point lacks
/// authorization. With `directive` set, an inline suppression comment sits above
/// the entry point.
fn write_suppression_project(dir: &std::path::Path, directive: bool) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"vault\"\nversion = \"0.1.0\"\n\n[dependencies]\nsoroban-sdk = \"21.0.0\"\n",
    )
    .unwrap();

    let mut src = String::new();
    src.push_str("use soroban_sdk::{contractimpl, symbol_short, Address, Env};\n\n");
    src.push_str("#[contractimpl]\n");
    src.push_str("impl Vault {\n");
    if directive {
        src.push_str("    // soroban-scan: ignore SS-001 -- reviewed by the security team\n");
    }
    src.push_str("    pub fn set_admin(env: Env, new_admin: Address) {\n");
    src.push_str(
        "        env.storage().persistent().set(&symbol_short!(\"ADMIN\"), &new_admin);\n",
    );
    src.push_str("    }\n");
    src.push_str("}\n");
    std::fs::write(dir.join("src/lib.rs"), src).unwrap();
}

fn rule_ids(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|finding| finding["rule_id"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn inline_suppressions_are_applied_and_reported() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-scan-cli-suppression-{}",
        std::process::id()
    ));

    // Without a directive the finding is reported and fails the gate.
    write_suppression_project(&dir, false);
    let plain = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--format",
        "json",
        "--rule",
        "SS-001",
        "--fail-on",
        "high",
    ]);
    assert_eq!(plain.code, 1, "an unsuppressed SS-001 must fail the gate");
    let value: serde_json::Value = serde_json::from_str(&plain.stdout).unwrap();
    assert!(rule_ids(&value["findings"]).contains(&"SS-001".to_string()));
    assert_eq!(value["stats"]["findings_suppressed"], 0);

    // With the directive the finding leaves the gate but is still reported.
    write_suppression_project(&dir, true);
    let suppressed = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--format",
        "json",
        "--rule",
        "SS-001",
        "--fail-on",
        "high",
    ]);
    assert_eq!(
        suppressed.code, 0,
        "suppressed findings must not fail the gate: {}",
        suppressed.stdout
    );
    let value: serde_json::Value = serde_json::from_str(&suppressed.stdout).unwrap();
    assert_eq!(value["stats"]["suppressions_detected"], 1);
    assert_eq!(value["stats"]["findings_suppressed"], 1);
    assert!(!rule_ids(&value["findings"]).contains(&"SS-001".to_string()));
    assert_eq!(value["suppressed"][0]["rule_id"], "SS-001");
    assert_eq!(value["suppressed"][0]["suppression"]["file"], "src/lib.rs");
    assert_eq!(value["suppressed"][0]["suppression"]["rules"], "SS-001");
    assert_eq!(
        value["suppressed"][0]["suppression"]["reason"],
        "reviewed by the security team"
    );
    assert_eq!(value["suppressions"][0]["applied"], true);

    // The terminal report surfaces the count, the directive and the reason.
    let terminal = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--rule",
        "SS-001",
        "--fail-on",
        "high",
    ]);
    assert_eq!(terminal.code, 0);
    assert!(
        terminal.stdout.contains("1 suppressed finding(s)"),
        "{}",
        terminal.stdout
    );
    assert!(terminal.stdout.contains("reviewed by the security team"));

    // SARIF keeps the result and marks it as an in-source suppression.
    let sarif = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--format",
        "sarif",
        "--rule",
        "SS-001",
        "--fail-on",
        "high",
    ]);
    let value: serde_json::Value = serde_json::from_str(&sarif.stdout).unwrap();
    let results = value["runs"][0]["results"].as_array().unwrap();
    let marked = results
        .iter()
        .find(|result| result["ruleId"] == "SS-001")
        .expect("SS-001 result stays in SARIF");
    assert_eq!(marked["suppressions"][0]["kind"], "inSource");
    assert_eq!(marked["suppressions"][0]["status"], "accepted");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn category_filters_apply_to_scans() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-scan-cli-categories-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    write_suppression_project(&dir, false);
    let config = dir.join("category-filter.toml");

    // Disabling `authorization` skips SS-001 even when the rule is requested.
    std::fs::write(
        &config,
        "[rules]\ndisabled_categories = [\"authorization\"]\n",
    )
    .unwrap();
    let disabled = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--format",
        "json",
        "--rule",
        "SS-001",
        "--fail-on",
        "none",
    ]);
    assert_eq!(disabled.code, 0, "{}", disabled.stderr);
    let value: serde_json::Value = serde_json::from_str(&disabled.stdout).unwrap();
    assert!(
        value["findings"].as_array().unwrap().is_empty(),
        "{}",
        disabled.stdout
    );

    // Selecting only `authorization` keeps the same rule active.
    std::fs::write(
        &config,
        "[rules]\nenabled_categories = [\"authorization\"]\n",
    )
    .unwrap();
    let enabled = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--format",
        "json",
        "--rule",
        "SS-001",
        "--fail-on",
        "none",
    ]);
    assert_eq!(enabled.code, 0, "{}", enabled.stderr);
    let value: serde_json::Value = serde_json::from_str(&enabled.stdout).unwrap();
    assert!(rule_ids(&value["findings"]).contains(&"SS-001".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_validate_rejects_unknown_category() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-scan-cli-bad-category-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("bad-category.toml");
    std::fs::write(&config, "[rules]\ndisabled_categories = [\"nonsense\"]\n").unwrap();

    let out = run(&["config", "validate", "--config", config.to_str().unwrap()]);
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(
        out.stderr.contains("unknown category"),
        "stderr: {}",
        out.stderr
    );
}

#[test]
fn exclude_tests_skips_cfg_test_items_and_test_directories() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-tests-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::create_dir_all(dir.join("tests")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"tests-demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nsoroban-sdk = \"21.0.0\"\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("src/lib.rs"),
        r#"
#[contractimpl]
impl C {
    pub fn vulnerable(env: Env) {
        env.storage().persistent().set(&Key::V, &1);
    }

    #[cfg(test)]
    pub fn test_only(env: Env) {
        env.storage().persistent().set(&Key::T, &1);
    }
}

#[cfg(test)]
mod tests {
    #[contractimpl]
    impl C {
        pub fn nested_test(env: Env) {
            env.storage().persistent().set(&Key::N, &1);
        }
    }
}
"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("tests/integration.rs"),
        r#"
#[contractimpl]
impl T {
    pub fn integration(env: Env) {
        env.storage().persistent().set(&Key::I, &1);
    }
}
"#,
    )
    .unwrap();

    let plain = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--rule",
        "SS-001",
        "--format",
        "json",
        "--fail-on",
        "none",
    ]);
    assert_eq!(plain.code, 0, "stderr: {}", plain.stderr);
    let value: serde_json::Value = serde_json::from_str(&plain.stdout).unwrap();
    assert_eq!(
        rule_ids(&value["findings"]).len(),
        4,
        "test-only code must be scanned by default: {}",
        plain.stdout
    );

    let excluded = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--rule",
        "SS-001",
        "--format",
        "json",
        "--fail-on",
        "none",
        "--exclude-tests",
    ]);
    assert_eq!(excluded.code, 0, "stderr: {}", excluded.stderr);
    let value: serde_json::Value = serde_json::from_str(&excluded.stdout).unwrap();
    let findings = value["findings"].as_array().unwrap();
    assert_eq!(
        findings.len(),
        1,
        "only the non-test finding may remain: {}",
        excluded.stdout
    );
    assert!(findings[0]["location"]["file"]
        .as_str()
        .unwrap()
        .ends_with("src/lib.rs"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_config_ignores_discovered_configuration() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-noconf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // A minimal project with an SS-001 finding plus a repository-provided
    // configuration that would hide it.
    write_suppression_project(&dir, false);
    let repo_config = dir.join("soroban-scan.toml");
    std::fs::write(&repo_config, "min_severity = \"critical\"\n").unwrap();

    // The discovered configuration filters the high-severity finding out.
    let discovered = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--format",
        "json",
        "--rule",
        "SS-001",
        "--fail-on",
        "high",
    ]);
    assert_eq!(discovered.code, 0, "{}", discovered.stdout);
    let value: serde_json::Value = serde_json::from_str(&discovered.stdout).unwrap();
    assert!(
        value["findings"].as_array().unwrap().is_empty(),
        "the repository configuration must be applied by default: {}",
        discovered.stdout
    );

    // --no-config ignores it: the finding is reported and fails the gate.
    let ignored = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--no-config",
        "--format",
        "json",
        "--rule",
        "SS-001",
        "--fail-on",
        "high",
    ]);
    assert_eq!(ignored.code, 1, "{}", ignored.stdout);
    let value: serde_json::Value = serde_json::from_str(&ignored.stdout).unwrap();
    assert!(rule_ids(&value["findings"]).contains(&"SS-001".to_string()));

    // It cannot be combined with --config.
    let both = run(&[
        "scan",
        dir.to_str().unwrap(),
        "--no-config",
        "--config",
        repo_config.to_str().unwrap(),
    ]);
    assert_eq!(both.code, 2, "{}", both.stderr);
    assert!(both.stderr.contains("--no-config"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn findings_are_rendered_in_the_documented_order() {
    let dir = std::env::temp_dir().join(format!("soroban-scan-cli-order-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();

    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"ordering-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nsoroban-sdk = \"20\"\n",
    )
    .unwrap();

    let address_a = format!("G{}B", "A".repeat(54));
    let address_b = format!("G{}C", "A".repeat(54));
    let address_c = format!("G{}D", "A".repeat(54));
    std::fs::write(
        dir.join("src/a.rs"),
        format!(
            "use soroban_sdk::contractimpl;\n\n#[contractimpl]\nimpl C {{\n    pub fn addrs() -> (&'static str, &'static str) {{ (\"{address_a}\", \"{address_b}\") }}\n}}\n"
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("src/b.rs"),
        format!(
            "use soroban_sdk::contractimpl;\n\n#[contractimpl]\nimpl D {{\n    pub fn addr() -> &'static str {{ \"{address_c}\" }}\n}}\n"
        ),
    )
    .unwrap();

    let out = run_in(
        &dir,
        &[
            "scan",
            ".",
            "--format",
            "json",
            "--fail-on",
            "none",
            "--no-config",
        ],
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let ordered: Vec<(String, usize, Option<usize>, String)> = value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["rule_id"] == "SS-007")
        .map(|finding| {
            (
                finding["location"]["file"].as_str().unwrap().to_string(),
                finding["location"]["line"].as_u64().unwrap() as usize,
                finding["location"]["column"].as_u64().map(|c| c as usize),
                finding["evidence"].as_str().unwrap().to_string(),
            )
        })
        .collect();

    assert_eq!(ordered.len(), 3, "findings: {ordered:?}");
    assert_eq!(ordered[0].0, "src/a.rs");
    assert_eq!(ordered[1].0, "src/a.rs");
    assert_eq!(ordered[2].0, "src/b.rs");
    // Same file and line: the column tie-break is ascending.
    assert_eq!(ordered[0].1, ordered[1].1);
    assert!(ordered[0].2.unwrap() < ordered[1].2.unwrap());
    assert!(ordered[0].3.contains(&address_a));
    assert!(ordered[1].3.contains(&address_b));
    assert!(ordered[2].3.contains(&address_c));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn json_report_records_the_effective_configuration() {
    let dir = std::env::temp_dir().join(format!(
        "soroban-scan-cli-effective-config-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("scan.toml");
    std::fs::write(
        &config,
        "[rules]\ndisabled = [\"SS-007\"]\nenabled = [\"SS-001\"]\nseverity_overrides = { SS-001 = \"critical\" }\nconfidence_overrides = { SS-001 = \"high\" }\n",
    )
    .unwrap();

    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--format",
        "json",
        "--min-severity",
        "medium",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);

    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let effective = &value["effective_config"];
    assert_eq!(effective["min_severity"], "medium");
    assert_eq!(effective["min_confidence"], "low");
    assert_eq!(effective["rules"]["disabled"][0], "SS-007");
    assert_eq!(effective["rules"]["enabled"][0], "SS-001");
    assert_eq!(
        effective["rules"]["severity_overrides"]["SS-001"],
        "critical"
    );
    assert_eq!(effective["rules"]["confidence_overrides"]["SS-001"], "high");
    assert!(effective["ai"]["enabled"] == false);
    assert!(effective["ai"]["provider"].is_null());
    assert!(effective.get("environment").is_none());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn scan_color_never_emits_no_ansi_escapes() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--quiet",
        "--color",
        "never",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(!out.stdout.contains('\u{1b}'), "got: {:?}", out.stdout);
}

#[test]
fn scan_color_always_emits_ansi_for_terminal_format() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--quiet",
        "--color",
        "always",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(out.stdout.contains('\u{1b}'), "got: {:?}", out.stdout);
}

#[test]
fn scan_color_auto_is_plain_when_stdout_is_not_a_tty() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--quiet",
        "--color",
        "auto",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(!out.stdout.contains('\u{1b}'), "got: {:?}", out.stdout);
}

#[test]
fn scan_color_auto_respects_no_color() {
    let out = run_with_env(
        &[
            "scan",
            fixture("corpus/SS-001").to_str().unwrap(),
            "--quiet",
            "--color",
            "auto",
            "--fail-on",
            "none",
        ],
        &[("NO_COLOR", "1")],
    );
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(!out.stdout.contains('\u{1b}'), "got: {:?}", out.stdout);
}

#[test]
fn scan_machine_formats_never_contain_ansi_even_with_color_always() {
    for format in ["json", "sarif", "markdown", "github"] {
        let out = run(&[
            "scan",
            fixture("corpus/SS-001").to_str().unwrap(),
            "--format",
            format,
            "--color",
            "always",
            "--fail-on",
            "none",
        ]);
        assert_eq!(out.code, 0, "format {format}: {}", out.stderr);
        assert!(
            !out.stdout.contains('\u{1b}'),
            "format {format} leaked ANSI: {:?}",
            out.stdout
        );
    }
}

#[test]
fn scan_json_includes_the_report_schema_version() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--format",
        "json",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(
        value["schema_version"],
        soroban_scan_core::report::REPORT_SCHEMA_VERSION
    );
    assert_eq!(value["schema_version"], "1");
}

#[test]
fn max_findings_truncates_deterministically_without_changing_the_gate() {
    let corpus = fixture("corpus");
    let corpus = corpus.to_str().unwrap();

    let full = run(&[
        "scan",
        corpus,
        "--format",
        "json",
        "--fail-on",
        "none",
        "--no-config",
    ]);
    assert_eq!(full.code, 0, "stderr: {}", full.stderr);
    let full_value: serde_json::Value = serde_json::from_str(&full.stdout).unwrap();
    let total = full_value["findings"].as_array().unwrap().len();
    assert!(total > 2, "need several findings to truncate, got {total}");
    assert!(full_value.get("truncation").is_none());

    let limited = run(&[
        "scan",
        corpus,
        "--format",
        "json",
        "--fail-on",
        "none",
        "--max-findings",
        "2",
        "--no-config",
    ]);
    assert_eq!(limited.code, 0, "stderr: {}", limited.stderr);
    let limited_value: serde_json::Value = serde_json::from_str(&limited.stdout).unwrap();
    let findings = limited_value["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 2, "{}", limited.stdout);
    assert_eq!(limited_value["truncation"]["shown"], 2);
    assert_eq!(limited_value["truncation"]["total"], total);
    assert_eq!(limited_value["truncation"]["omitted"], total - 2);
    // Truncation keeps the first rows of the already-sorted report.
    for (shown, original) in findings
        .iter()
        .zip(full_value["findings"].as_array().unwrap())
    {
        assert_eq!(shown["fingerprint"], original["fingerprint"]);
    }

    // The gate considers every finding, even when none is displayed.
    let gated = run(&[
        "scan",
        corpus,
        "--max-findings",
        "0",
        "--quiet",
        "--no-config",
    ]);
    assert_eq!(
        gated.code, 1,
        "--max-findings must not change the exit gate: {}",
        gated.stdout
    );
    assert!(
        gated
            .stdout
            .contains(&format!("{total} more finding(s) not shown")),
        "the terminal report must state what it omitted: {}",
        gated.stdout
    );

    let markdown = run(&[
        "scan",
        corpus,
        "--format",
        "markdown",
        "--fail-on",
        "none",
        "--max-findings",
        "1",
        "--no-config",
    ]);
    assert!(
        markdown
            .stdout
            .contains(&format!("{} more finding(s)", total - 1)),
        "markdown must state what it omitted: {}",
        markdown.stdout
    );

    let github = run(&[
        "scan",
        corpus,
        "--format",
        "github",
        "--fail-on",
        "none",
        "--max-findings",
        "1",
        "--no-config",
    ]);
    assert!(
        github.stdout.contains("::notice::") && github.stdout.contains("more finding(s)"),
        "github output must state what it omitted: {}",
        github.stdout
    );
}

fn write_policy_project(dir: &Path, with_new_finding: bool) {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"policy-demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nsoroban-sdk = \"21.0.0\"\n",
    )
    .unwrap();

    let mut src = String::from(
        "use soroban_sdk::{contractimpl, symbol_short, Address, Env};\n\n#[contractimpl]\nimpl Vault {\n",
    );
    src.push_str("    pub fn set_admin(env: Env, admin: Address) {\n");
    src.push_str("        env.storage().persistent().set(&symbol_short!(\"ADMIN\"), &admin);\n");
    src.push_str("    }\n");
    if with_new_finding {
        src.push_str("    pub fn set_owner(env: Env, owner: Address) {\n");
        src.push_str(
            "        env.storage().persistent().set(&symbol_short!(\"OWNER\"), &owner);\n",
        );
        src.push_str("    }\n");
    }
    src.push_str("}\n");
    std::fs::write(dir.join("src/lib.rs"), src).unwrap();
}

fn run_policy_scan(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec![
        "scan".to_string(),
        dir.to_string_lossy().into_owned(),
        "--format".to_string(),
        "json".to_string(),
        "--rule".to_string(),
        "SS-001".to_string(),
        "--no-config".to_string(),
    ];
    args.extend(extra.iter().map(|arg| arg.to_string()));
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&refs)
}

fn reported_findings(out: &Output) -> usize {
    let value: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    value["findings"].as_array().unwrap().len()
}

#[test]
fn baseline_new_only_fail_on_policy_matrix() {
    let root = std::env::temp_dir().join(format!(
        "soroban-scan-cli-policy-matrix-{}",
        std::process::id()
    ));
    let dir = root.join("project");
    let baseline = root.join("baseline.json");
    std::fs::create_dir_all(&root).unwrap();
    write_policy_project(&dir, false);

    let write = run_policy_scan(
        &dir,
        &[
            "--write-baseline",
            baseline.to_str().unwrap(),
            "--fail-on",
            "none",
        ],
    );
    assert_eq!(write.code, 0, "stderr: {}", write.stderr);

    // The baseline has one known high finding. Without new findings, the gate
    // ignores it even though the report still lists it.
    let known = run_policy_scan(
        &dir,
        &[
            "--baseline",
            baseline.to_str().unwrap(),
            "--fail-on",
            "high",
        ],
    );
    assert_eq!(
        known.code, 0,
        "known findings must not fail: {}",
        known.stdout
    );
    assert_eq!(reported_findings(&known), 1);

    let known_new_only = run_policy_scan(
        &dir,
        &[
            "--baseline",
            baseline.to_str().unwrap(),
            "--new-only",
            "--fail-on",
            "high",
        ],
    );
    assert_eq!(known_new_only.code, 0);
    assert_eq!(reported_findings(&known_new_only), 0);

    // Without a baseline, every finding is gated and --new-only is a usage error.
    let no_baseline_high = run_policy_scan(&dir, &["--fail-on", "high"]);
    assert_eq!(no_baseline_high.code, 1);
    assert_eq!(reported_findings(&no_baseline_high), 1);

    let no_baseline_new_only = run_policy_scan(&dir, &["--new-only", "--fail-on", "high"]);
    assert_eq!(no_baseline_new_only.code, 2);

    // Add a second high finding that is not in the baseline.
    write_policy_project(&dir, true);

    let cases: &[(&[&str], i32, usize)] = &[
        // Known + new are reported; only the new one is gated.
        (&["--baseline", "BASE", "--fail-on", "high"], 1, 2),
        // --new-only changes the report but not the gate.
        (
            &["--baseline", "BASE", "--new-only", "--fail-on", "high"],
            1,
            1,
        ),
        // A higher threshold ignores both high findings, known or new.
        (&["--baseline", "BASE", "--fail-on", "critical"], 0, 2),
        (
            &["--baseline", "BASE", "--new-only", "--fail-on", "critical"],
            0,
            1,
        ),
        // --fail-on none always exits successfully.
        (&["--baseline", "BASE", "--fail-on", "none"], 0, 2),
        (
            &["--baseline", "BASE", "--new-only", "--fail-on", "none"],
            0,
            1,
        ),
        // --incremental only suppresses resolved reporting; the gate is unchanged.
        (
            &["--baseline", "BASE", "--incremental", "--fail-on", "high"],
            1,
            2,
        ),
    ];

    let baseline = baseline.to_str().unwrap();
    for (extra, expected_code, expected_findings) in cases {
        let resolved: Vec<&str> = extra
            .iter()
            .map(|arg| if *arg == "BASE" { baseline } else { *arg })
            .collect();
        let out = run_policy_scan(&dir, &resolved);
        assert_eq!(
            out.code, *expected_code,
            "args {resolved:?} produced the wrong exit code: {}",
            out.stdout
        );
        assert_eq!(
            reported_findings(&out),
            *expected_findings,
            "args {resolved:?} reported the wrong number of findings: {}",
            out.stdout
        );
    }

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn scan_github_format_emits_one_annotation_per_finding() {
    let out = run(&[
        "scan",
        fixture("corpus/SS-001").to_str().unwrap(),
        "--format",
        "github",
        "--fail-on",
        "none",
    ]);
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert!(!out.stdout.is_empty(), "expected annotation output");
    for line in out.stdout.lines() {
        assert!(
            line.starts_with("::error ")
                || line.starts_with("::warning ")
                || line.starts_with("::notice "),
            "unexpected annotation: {line:?}"
        );
        assert!(line.contains("file="), "{line}");
        assert!(line.contains("line="), "{line}");
        assert!(line.contains("title="), "{line}");
    }
}
