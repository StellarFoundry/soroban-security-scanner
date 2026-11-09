//! Read-only regression corpus coverage report.
//!
//! Summarizes per-rule positive and negative fixture counts, detector
//! documentation presence, and validation status in terminal or Markdown format.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Minimum number of negative fixtures required per rule by the corpus gate.
pub const MIN_NEGATIVES_PER_RULE: usize = 3;

/// Output format for the corpus coverage report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum ReportFormat {
    /// Human-readable aligned table.
    #[default]
    Terminal,
    /// GitHub-flavored Markdown table.
    Markdown,
}

/// Coverage record for a single rule id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleCoverage {
    /// Rule identifier (for example `SS-001`).
    pub rule_id: String,
    /// Number of `positive*.rs` / `positive*.toml` fixtures.
    pub positives: usize,
    /// Number of `negative*.rs` / `negative*.toml` fixtures.
    pub negatives: usize,
    /// Number of `must_trigger*` / `must-trigger*` fixtures, when present.
    pub must_trigger: usize,
    /// Whether `docs/rules/detectors/<ID>.md` exists and is non-empty.
    pub has_docs: bool,
    /// Validation gaps discovered for this rule (empty means valid).
    pub issues: Vec<String>,
}

impl RuleCoverage {
    /// Returns `true` when the rule meets all corpus and documentation requirements.
    pub fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    /// Short validation status label (`ok` or comma-separated gap summary).
    pub fn status_label(&self) -> String {
        if self.issues.is_empty() {
            "ok".to_string()
        } else {
            format!("gap ({})", self.issues.join(", "))
        }
    }
}

/// Aggregated corpus coverage report across all discovered rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusReport {
    /// Per-rule rows, sorted deterministically by rule id.
    pub rows: Vec<RuleCoverage>,
}

impl CorpusReport {
    /// Returns `true` when every rule in the report passes validation.
    pub fn is_complete(&self) -> bool {
        !self.rows.is_empty() && self.rows.iter().all(RuleCoverage::is_valid)
    }

    /// Number of rules with no validation gaps.
    pub fn valid_count(&self) -> usize {
        self.rows.iter().filter(|row| row.is_valid()).count()
    }

    /// Total number of positive fixtures across all rules.
    pub fn total_positives(&self) -> usize {
        self.rows.iter().map(|row| row.positives).sum()
    }

    /// Total number of negative fixtures across all rules.
    pub fn total_negatives(&self) -> usize {
        self.rows.iter().map(|row| row.negatives).sum()
    }

    /// Renders the report in the requested format.
    pub fn render(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Terminal => self.render_terminal(),
            ReportFormat::Markdown => self.render_markdown(),
        }
    }

    fn render_terminal(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "{:<8} {:>9} {:>9} {:>12} {:<6} {}\n",
            "RULE", "POSITIVES", "NEGATIVES", "MUST-TRIGGER", "DOCS", "STATUS"
        ));
        out.push_str(&format!(
            "{:-<8} {:->9} {:->9} {:->12} {:-<6} {:-<6}\n",
            "", "", "", "", "", ""
        ));
        for row in &self.rows {
            let docs = if row.has_docs { "yes" } else { "no" };
            out.push_str(&format!(
                "{:<8} {:>9} {:>9} {:>12} {:<6} {}\n",
                row.rule_id,
                row.positives,
                row.negatives,
                row.must_trigger,
                docs,
                row.status_label()
            ));
        }
        out.push_str(&format!(
            "\nSummary: {}/{} rules complete ({} positive, {} negative fixtures)\n",
            self.valid_count(),
            self.rows.len(),
            self.total_positives(),
            self.total_negatives()
        ));
        out
    }

    fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("| Rule | Positives | Negatives | Must-Trigger | Docs | Status |\n");
        out.push_str("| ---- | --------: | --------: | -----------: | :--- | :----- |\n");
        for row in &self.rows {
            let docs = if row.has_docs { "yes" } else { "no" };
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                row.rule_id,
                row.positives,
                row.negatives,
                row.must_trigger,
                docs,
                row.status_label()
            ));
        }
        out.push_str(&format!(
            "\n**Summary:** {}/{} rules complete ({} positive, {} negative fixtures).\n",
            self.valid_count(),
            self.rows.len(),
            self.total_positives(),
            self.total_negatives()
        ));
        out
    }
}

/// Inspects `root` read-only and builds the corpus coverage report.
pub fn analyze(root: &Path) -> Result<CorpusReport, String> {
    if !root.is_dir() {
        return Err(format!("{} is not a directory", root.display()));
    }

    let corpus_dir = root.join("fixtures").join("corpus");
    let detectors_dir = root.join("docs").join("rules").join("detectors");
    let rules_src_dir = root
        .join("crates")
        .join("soroban-scan-core")
        .join("src")
        .join("rules");

    let mut rule_ids = BTreeSet::new();
    collect_rule_ids_from_corpus(&corpus_dir, &mut rule_ids)?;
    collect_rule_ids_from_docs(&detectors_dir, &mut rule_ids)?;
    collect_rule_ids_from_sources(&rules_src_dir, &mut rule_ids)?;

    if rule_ids.is_empty() {
        return Err(format!("no rules discovered under {}", root.display()));
    }

    let mut rows = Vec::with_capacity(rule_ids.len());
    for rule_id in rule_ids {
        let rule_corpus = corpus_dir.join(&rule_id);
        let (positives, negatives, must_trigger) = count_fixtures(&rule_corpus)?;
        let doc_path = detectors_dir.join(format!("{rule_id}.md"));
        let has_docs = fs::metadata(&doc_path)
            .map(|meta| meta.is_file() && meta.len() > 0)
            .unwrap_or(false);

        let mut issues = Vec::new();
        if positives == 0 {
            issues.push("missing positive".to_string());
        }
        if negatives < MIN_NEGATIVES_PER_RULE {
            issues.push(format!("negatives {negatives}/{MIN_NEGATIVES_PER_RULE}"));
        }
        if !has_docs {
            issues.push("missing docs".to_string());
        }

        rows.push(RuleCoverage {
            rule_id,
            positives,
            negatives,
            must_trigger,
            has_docs,
            issues,
        });
    }

    Ok(CorpusReport { rows })
}

fn is_rule_id(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("SS-") else {
        return false;
    };
    rest.len() == 3 && rest.chars().all(|c| c.is_ascii_digit())
}

fn collect_rule_ids_from_corpus(
    corpus_dir: &Path,
    ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !corpus_dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(corpus_dir)
        .map_err(|err| format!("failed to read {}: {err}", corpus_dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", corpus_dir.display()))?;
        if entry.path().is_dir() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_rule_id(&name) {
                ids.insert(name);
            }
        }
    }
    Ok(())
}

fn collect_rule_ids_from_docs(
    detectors_dir: &Path,
    ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !detectors_dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(detectors_dir)
        .map_err(|err| format!("failed to read {}: {err}", detectors_dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", detectors_dir.display()))?;
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|ext| ext == "md") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                if is_rule_id(stem) {
                    ids.insert(stem.to_string());
                }
            }
        }
    }
    Ok(())
}

fn collect_rule_ids_from_sources(
    rules_src_dir: &Path,
    ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    if !rules_src_dir.is_dir() {
        return Ok(());
    }
    let entries = fs::read_dir(rules_src_dir)
        .map_err(|err| format!("failed to read {}: {err}", rules_src_dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| format!("failed to read {}: {err}", rules_src_dir.display()))?;
        let path = entry.path();
        if !path.is_file() || !path.extension().is_some_and(|ext| ext == "rs") {
            continue;
        }
        let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if matches!(
            file_name,
            "mod.rs" | "util.rs" | "validation.rs" | "test_support.rs"
        ) {
            continue;
        }
        let content = fs::read_to_string(&path)
            .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("id: \"") {
                if let Some(id) = rest.split('"').next() {
                    if is_rule_id(id) {
                        ids.insert(id.to_string());
                    }
                }
            }
        }
    }
    Ok(())
}

fn is_fixture_ext(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext == "rs" || ext == "toml")
}

fn count_fixtures(rule_dir: &Path) -> Result<(usize, usize, usize), String> {
    if !rule_dir.is_dir() {
        return Ok((0, 0, 0));
    }
    let mut positives = 0usize;
    let mut negatives = 0usize;
    let mut must_trigger = 0usize;

    let entries = fs::read_dir(rule_dir)
        .map_err(|err| format!("failed to read {}: {err}", rule_dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("failed to read {}: {err}", rule_dir.display()))?;
        let path = entry.path();
        if !path.is_file() || !is_fixture_ext(&path) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with("positive") {
            positives += 1;
        } else if name.starts_with("negative") {
            negatives += 1;
        } else if name.starts_with("must_trigger") || name.starts_with("must-trigger") {
            must_trigger += 1;
        }
    }
    Ok((positives, negatives, must_trigger))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    }

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("xtask-corpus-{label}-{nanos}"));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn current_corpus_is_complete_and_renders_both_formats() {
        let report = analyze(&workspace_root()).expect("corpus analysis must succeed");
        assert!(
            report.rows.len() >= 19,
            "expected at least 19 built-in rules, got {}",
            report.rows.len()
        );
        assert!(
            report.is_complete(),
            "current corpus has unexpected gaps: {:#?}",
            report.rows
        );

        let terminal = report.render(ReportFormat::Terminal);
        assert!(terminal.contains("SS-001"));
        assert!(terminal.contains("SS-015"));
        assert!(terminal.contains("Summary:"));

        let markdown = report.render(ReportFormat::Markdown);
        assert!(markdown.starts_with("| Rule | Positives | Negatives |"));
        assert!(markdown.contains("| SS-001 |"));
        assert!(markdown.contains("**Summary:**"));
    }

    #[test]
    fn reports_missing_negatives_and_docs_without_modifying_files() {
        let root = temp_root("gaps");
        let ss001 = root.join("fixtures/corpus/SS-001");
        let ss002 = root.join("fixtures/corpus/SS-002");
        let docs = root.join("docs/rules/detectors");
        fs::create_dir_all(&ss001).unwrap();
        fs::create_dir_all(&ss002).unwrap();
        fs::create_dir_all(&docs).unwrap();

        for name in ["positive.rs", "negative.rs", "negative2.rs", "negative3.rs"] {
            fs::write(ss001.join(name), "pub fn ok() {}\n").unwrap();
        }
        fs::write(docs.join("SS-001.md"), "# SS-001\n").unwrap();

        // SS-002 has only one negative and no docs.
        fs::write(ss002.join("positive.rs"), "pub fn bad() {}\n").unwrap();
        fs::write(ss002.join("negative.rs"), "pub fn good() {}\n").unwrap();

        let report = analyze(&root).unwrap();
        assert_eq!(report.rows.len(), 2);
        assert!(!report.is_complete());
        assert_eq!(report.valid_count(), 1);
        assert!(report.rows[0].is_valid());
        assert!(!report.rows[1].is_valid());
        assert!(report.rows[1].status_label().contains("negatives 1/3"));
        assert!(report.rows[1].status_label().contains("missing docs"));

        fs::remove_dir_all(&root).unwrap();
    }
}
