//! Corpus coverage reporting (#140).
//!
//! Read-only view of each rule's fixture counts, documentation, and
//! must-trigger sample. The same data drives the on-demand report and the
//! coverage test.

use std::path::{Path, PathBuf};

use crate::registry::RuleRegistry;

/// Coverage for one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusCoverageRow {
    /// Rule id.
    pub rule_id: String,
    /// Number of `positive*` fixtures.
    pub positives: usize,
    /// Number of `negative*` fixtures.
    pub negatives: usize,
    /// Whether `docs/rules/detectors/<ID>.md` exists.
    pub documented: bool,
    /// Whether a must-trigger sample exists.
    pub must_trigger: bool,
}

impl CorpusCoverageRow {
    /// Whether the row satisfies the minimum corpus contract.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.positives >= 1 && self.negatives >= 3 && self.documented && self.must_trigger
    }
}

fn fixture_count(dir: &Path, prefix: &str) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                return false;
            };
            name.starts_with(prefix)
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| extension == "rs" || extension == "toml")
        })
        .count()
}

/// Collect coverage for every registered rule under `root`.
#[must_use]
pub fn coverage(root: &Path, registry: &RuleRegistry) -> Vec<CorpusCoverageRow> {
    registry
        .metadata_sorted()
        .iter()
        .map(|meta| {
            let corpus_dir = root.join("fixtures").join("corpus").join(meta.id);
            let docs = root
                .join("docs")
                .join("rules")
                .join("detectors")
                .join(format!("{}.md", meta.id));
            let must_trigger_dir = root.join("fixtures").join("must-trigger");
            let must_trigger = ["rs", "toml"].iter().any(|extension| {
                must_trigger_dir
                    .join(format!("{}.{}", meta.id, extension))
                    .is_file()
            });
            CorpusCoverageRow {
                rule_id: meta.id.to_string(),
                positives: fixture_count(&corpus_dir, "positive"),
                negatives: fixture_count(&corpus_dir, "negative"),
                documented: docs.is_file(),
                must_trigger,
            }
        })
        .collect()
}

/// Render the report as aligned plain text.
#[must_use]
pub fn render_terminal(rows: &[CorpusCoverageRow]) -> String {
    let mut out = String::from("rule      positives negatives docs must-trigger complete\n");
    for row in rows {
        out.push_str(&format!(
            "{:<9} {:>9} {:>9} {:>4} {:>12} {:>8}\n",
            row.rule_id,
            row.positives,
            row.negatives,
            if row.documented { "yes" } else { "no" },
            if row.must_trigger { "yes" } else { "no" },
            if row.complete() { "yes" } else { "no" },
        ));
    }
    out
}

/// Render the report as a Markdown table.
#[must_use]
pub fn render_markdown(rows: &[CorpusCoverageRow]) -> String {
    let mut out = String::from(
        "| Rule | Positives | Negatives | Docs | Must-trigger | Complete |\n\
         | ---- | --------- | --------- | ---- | ------------ | -------- |\n",
    );
    for row in rows {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            row.rule_id,
            row.positives,
            row.negatives,
            if row.documented { "yes" } else { "no" },
            if row.must_trigger { "yes" } else { "no" },
            if row.complete() { "yes" } else { "no" },
        ));
    }
    out
}

/// Repository root used by the example and tests.
#[must_use]
pub fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_terminal_and_markdown() {
        let rows = vec![CorpusCoverageRow {
            rule_id: "SS-001".to_string(),
            positives: 1,
            negatives: 3,
            documented: true,
            must_trigger: true,
        }];
        let terminal = render_terminal(&rows);
        assert!(terminal.contains("SS-001"));
        assert!(terminal.contains("yes"));
        let markdown = render_markdown(&rows);
        assert!(markdown.contains("| SS-001 | 1 | 3 | yes | yes | yes |"));
    }
}
