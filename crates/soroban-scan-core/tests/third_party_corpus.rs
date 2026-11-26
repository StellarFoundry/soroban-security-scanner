//! Real-world third-party corpus scan test (#321).
//!
//! Every entry under `fixtures/third-party/` pins one or more upstream Rust
//! sources and records the findings they actually produce. Expectations are
//! generated from scanner output, reviewed, and then checked on every test run;
//! they are never inferred from rule names or hand-authored edges.
//!
//! Regenerate reviewed expectations only when scanner behavior intentionally
//! changes:
//!
//! ```text
//! UPDATE_THIRD_PARTY_EXPECTATIONS=1 cargo test -p soroban-scan-core --test third_party_corpus
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use soroban_scan_core::confidence::Confidence;
use soroban_scan_core::config::ScanConfig;
use soroban_scan_core::engine;
use soroban_scan_core::registry::RuleRegistry;
use soroban_scan_core::severity::Severity;

const MIN_ENTRIES: usize = 5;
const DEFAULT_NOTES: &str = "Findings generated from the pinned upstream source and reviewed; no edges or findings were invented.";
const VERIFIED_WITH: &str =
    "soroban-scan 0.2.0; ScanConfig::default; RuleRegistry::with_default_rules";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpectedManifest {
    schema_version: u32,
    entry: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verified_with: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    contracts: Vec<ExpectedContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpectedContract {
    file: String,
    findings: Vec<ExpectedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ExpectedFinding {
    rule_id: String,
    count: usize,
    severity: String,
    confidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActualFinding {
    count: usize,
    severity: String,
    confidence: String,
}

fn third_party_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/third-party")
}

fn entry_dirs(base: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && path.join("PROVENANCE.toml").is_file())
        .collect();
    dirs.sort();
    dirs
}

fn required_str(table: &toml::Table, key: &str) -> Result<String, String> {
    match table
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
    {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        _ => Err(format!("missing `{key}`")),
    }
}

fn has_commit_pin(url: &str) -> bool {
    url.split('/')
        .any(|part| part.len() == 40 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn safe_relative_source(value: &str) -> bool {
    if value.is_empty() || value.contains('\\') || value.starts_with('/') {
        return false;
    }
    let path = Path::new(value);
    path.components()
        .all(|part| matches!(part, Component::Normal(_)))
        && path.extension().and_then(OsStr::to_str) == Some("rs")
}

fn relative_source_files(dir: &Path) -> Vec<String> {
    let mut files: Vec<String> = WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            let relative = entry.path().strip_prefix(dir).ok()?;
            if relative.extension().and_then(OsStr::to_str) != Some("rs") {
                return None;
            }
            Some(relative.to_string_lossy().replace('\\', "/"))
        })
        .collect();
    files.sort();
    files
}

fn scan_contract(
    path: &Path,
    relative: &str,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> Result<BTreeMap<String, ActualFinding>, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read `{}`: {error}", path.display()))?;
    let outcome = engine::scan_source_str(&source, relative, config, registry);
    let mut actual = BTreeMap::new();
    for finding in outcome.findings {
        let entry = actual
            .entry(finding.rule_id)
            .or_insert_with(|| ActualFinding {
                count: 0,
                severity: finding.severity.to_string(),
                confidence: finding.confidence.to_string(),
            });
        entry.count += 1;
    }
    Ok(actual)
}

fn generate_manifest(
    dir: &Path,
    entry_name: &str,
    existing: Option<&ExpectedManifest>,
) -> Result<String, String> {
    let config = ScanConfig::default();
    let registry = RuleRegistry::with_default_rules();
    let mut contracts = Vec::new();
    for file in relative_source_files(dir) {
        let actual = scan_contract(&dir.join(&file), &file, &config, &registry)?;
        let findings = actual
            .into_iter()
            .map(|(rule_id, value)| ExpectedFinding {
                rule_id,
                count: value.count,
                severity: value.severity,
                confidence: value.confidence,
            })
            .collect();
        contracts.push(ExpectedContract { file, findings });
    }
    let manifest = ExpectedManifest {
        schema_version: 1,
        entry: entry_name.to_string(),
        verified_with: existing
            .and_then(|manifest| manifest.verified_with.clone())
            .or_else(|| Some(VERIFIED_WITH.to_string())),
        notes: existing
            .and_then(|manifest| manifest.notes.clone())
            .or_else(|| Some(DEFAULT_NOTES.to_string())),
        contracts,
    };
    toml::to_string_pretty(&manifest)
        .map_err(|error| format!("cannot serialize expected findings: {error}"))
}

fn check_entry(dir: &Path, update: bool) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let name = dir
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("third-party")
        .to_string();
    let provenance_text = match std::fs::read_to_string(dir.join("PROVENANCE.toml")) {
        Ok(text) => text,
        Err(error) => return Err(vec![format!("cannot read PROVENANCE.toml: {error}")]),
    };
    let provenance: toml::Table = match provenance_text.parse() {
        Ok(table) => table,
        Err(error) => return Err(vec![format!("invalid PROVENANCE.toml: {error}")]),
    };

    let source_url = match required_str(&provenance, "source_url") {
        Ok(url) => url,
        Err(error) => {
            errors.push(error);
            String::new()
        }
    };
    if !source_url.is_empty() && !source_url.starts_with("https://") {
        errors.push(format!("`source_url` must be https, got `{source_url}`"));
    }
    if !source_url.is_empty() && !has_commit_pin(&source_url) {
        errors.push(format!(
            "`source_url` must pin a 40-character commit, got `{source_url}`"
        ));
    }
    for field in ["license", "license_file", "secret_review"] {
        if let Err(error) = required_str(&provenance, field) {
            errors.push(error);
        }
    }
    if let Ok(license_file) = required_str(&provenance, "license_file") {
        if !dir.join(&license_file).is_file() {
            errors.push(format!("license file `{license_file}` does not exist"));
        }
    }

    let expected_relative = match required_str(&provenance, "expected_findings") {
        Ok(value) => value,
        Err(error) => {
            errors.push(error);
            return Err(errors);
        }
    };
    let relative_path = Path::new(&expected_relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        errors.push(format!(
            "`expected_findings` must stay inside the entry: `{expected_relative}`"
        ));
        return Err(errors);
    }
    let expected_path = dir.join(relative_path);
    if !expected_path.is_file() {
        errors.push(format!(
            "expected-findings manifest `{expected_relative}` does not exist"
        ));
        return Err(errors);
    }

    let existing: Option<ExpectedManifest> = std::fs::read_to_string(&expected_path)
        .ok()
        .and_then(|text| toml::from_str(&text).ok());
    if update {
        match generate_manifest(dir, &name, existing.as_ref()) {
            Ok(text) => std::fs::write(&expected_path, text).unwrap_or_else(|error| {
                panic!("cannot write {}: {error}", expected_path.display())
            }),
            Err(error) => {
                errors.push(error);
                return Err(errors);
            }
        }
    }

    let manifest_text = match std::fs::read_to_string(&expected_path) {
        Ok(text) => text,
        Err(error) => {
            errors.push(format!("cannot read expected findings: {error}"));
            return Err(errors);
        }
    };
    let manifest: ExpectedManifest = match toml::from_str(&manifest_text) {
        Ok(manifest) => manifest,
        Err(error) => {
            errors.push(format!("invalid expected findings TOML: {error}"));
            return Err(errors);
        }
    };
    if manifest.schema_version != 1 {
        errors.push(format!(
            "unsupported expected schema_version {}",
            manifest.schema_version
        ));
    }
    if manifest.entry != name {
        errors.push(format!(
            "manifest entry `{}` does not match directory `{name}`",
            manifest.entry
        ));
    }
    if manifest
        .verified_with
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        errors.push("missing `verified_with`".to_string());
    }
    if manifest
        .notes
        .as_deref()
        .is_none_or(|value| value.trim().is_empty())
    {
        errors.push("missing `notes`".to_string());
    }

    let registry = RuleRegistry::with_default_rules();
    let config = ScanConfig::default();
    let actual_files: BTreeSet<String> = relative_source_files(dir).into_iter().collect();
    if actual_files.is_empty() {
        errors.push("entry has no Rust source files".to_string());
    }
    let mut listed = BTreeSet::new();
    for contract in &manifest.contracts {
        if !safe_relative_source(&contract.file) {
            errors.push(format!("unsafe source path `{}`", contract.file));
            continue;
        }
        if !listed.insert(contract.file.clone()) {
            errors.push(format!("duplicate source entry `{}`", contract.file));
        }
        if !actual_files.contains(&contract.file) {
            errors.push(format!("manifest lists missing source `{}`", contract.file));
            continue;
        }
        let mut expected = BTreeMap::new();
        let mut seen_rules = BTreeSet::new();
        for finding in &contract.findings {
            if !seen_rules.insert(finding.rule_id.clone()) {
                errors.push(format!(
                    "source `{}` lists rule `{}` more than once",
                    contract.file, finding.rule_id
                ));
            }
            if finding.count == 0 {
                errors.push(format!(
                    "source `{}` has a zero expected count for `{}`",
                    contract.file, finding.rule_id
                ));
            }
            if registry.by_id(&finding.rule_id).is_none() {
                errors.push(format!(
                    "source `{}` expects unknown rule `{}`",
                    contract.file, finding.rule_id
                ));
            }
            if finding.severity.parse::<Severity>().is_err() {
                errors.push(format!(
                    "source `{}` has invalid severity `{}`",
                    contract.file, finding.severity
                ));
            }
            if finding.confidence.parse::<Confidence>().is_err() {
                errors.push(format!(
                    "source `{}` has invalid confidence `{}`",
                    contract.file, finding.confidence
                ));
            }
            expected.insert(
                finding.rule_id.clone(),
                ActualFinding {
                    count: finding.count,
                    severity: finding.severity.clone(),
                    confidence: finding.confidence.clone(),
                },
            );
        }
        let actual = match scan_contract(
            &dir.join(&contract.file),
            &contract.file,
            &config,
            &registry,
        ) {
            Ok(actual) => actual,
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        if actual != expected {
            errors.push(format!(
                "source `{}` findings changed: expected {:?}, got {:?}",
                contract.file, expected, actual
            ));
        }
    }
    for missing in actual_files.difference(&listed) {
        errors.push(format!("source `{missing}` has no manifest entry"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[test]
fn third_party_contracts_match_verified_findings() {
    let base = third_party_dir();
    let dirs = entry_dirs(&base);
    assert!(
        dirs.len() >= MIN_ENTRIES,
        "expected at least {MIN_ENTRIES} real-world third-party entries, found {}",
        dirs.len()
    );

    let update = std::env::var("UPDATE_THIRD_PARTY_EXPECTATIONS").as_deref() == Ok("1");
    let mut failures = Vec::new();
    for dir in dirs {
        if let Err(errors) = check_entry(&dir, update) {
            for error in errors {
                failures.push(format!("{}: {error}", dir.display()));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "third-party corpus failures:\n{}",
        failures.join("\n")
    );
}
