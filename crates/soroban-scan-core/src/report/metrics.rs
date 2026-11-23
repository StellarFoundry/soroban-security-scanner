//! Per-rule evaluation metrics over the labeled regression corpus.
//!
//! The report has one row per shipped rule, enumerated from the
//! [`RuleRegistry`]. It combines three sources of evidence:
//!
//! * **Findings** are counted from the scan of every fixture.
//! * **False positives and false negatives** are fixture-level labels from each
//!   rule's `expected.json` manifest. A positive fixture that does not trigger
//!   its rule is a false negative; a negative fixture that does trigger it is a
//!   false positive. Labels that cannot be classified unambiguously are counted
//!   separately and excluded from the metric totals; they are never guessed.
//! * **Runtime** is the measured elapsed microseconds per rule over the same
//!   fixture scans. Runtime is the only non-deterministic field; ordering,
//!   field order, and every other value are stable for the same inputs.
//!
//! The report contains only rule ids, metadata already published in the rule
//! catalog, counts, and durations. It never includes source text, evidence,
//! absolute paths, environment data, or user identifiers.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ScanConfig;
use crate::engine::{self, RuleTimingStatus, ScanOutcome};
use crate::registry::RuleRegistry;

/// Version of the rule evaluation metrics contract.
pub const METRICS_SCHEMA_VERSION: &str = "1";

/// A fixture used to evaluate one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixtureLabel {
    /// A fixture expected to trigger the rule.
    Positive,
    /// A fixture expected not to trigger the rule.
    Negative,
    /// A fixture whose label cannot be determined without guessing.
    Ambiguous,
}

/// One labeled fixture observation for a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixtureObservation {
    /// The rule being evaluated.
    pub rule_id: String,
    /// The fixture label.
    pub label: FixtureLabel,
    /// Number of times the rule fired in the fixture.
    pub actual_hits: usize,
}

/// Metrics for one shipped rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMetrics {
    /// Stable rule id.
    pub rule_id: String,
    /// Rule title from the catalog.
    pub title: String,
    /// Stable category name.
    pub category: String,
    /// Findings produced across the labeled corpus, including cross-rule hits.
    pub findings: usize,
    /// Positive fixtures that triggered the rule.
    pub true_positives: usize,
    /// Negative fixtures that incorrectly triggered the rule.
    pub false_positives: usize,
    /// Positive fixtures that did not trigger the rule.
    pub false_negatives: usize,
    /// Negative fixtures that correctly did not trigger the rule.
    pub true_negatives: usize,
    /// Positive fixtures evaluated for this rule.
    pub positive_fixtures: usize,
    /// Negative fixtures evaluated for this rule.
    pub negative_fixtures: usize,
    /// Fixtures whose label was ambiguous and therefore excluded.
    pub ambiguous_fixtures: usize,
    /// Measured runtime for this rule across the corpus, in microseconds.
    pub runtime_micros: u64,
    /// Execution status: `completed`, `timed_out`, `panicked`, or `not_run`.
    pub status: String,
}

/// Corpus totals across every shipped rule.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsTotals {
    /// Number of shipped rules covered.
    pub rules: usize,
    /// Total findings.
    pub findings: usize,
    /// Total true positives at fixture level.
    pub true_positives: usize,
    /// Total false positives at fixture level.
    pub false_positives: usize,
    /// Total false negatives at fixture level.
    pub false_negatives: usize,
    /// Total true negatives at fixture level.
    pub true_negatives: usize,
    /// Total ambiguous fixtures.
    pub ambiguous_fixtures: usize,
    /// Total measured runtime, in microseconds.
    pub runtime_micros: u64,
}

/// A deterministic, machine-readable rule evaluation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsReport {
    /// Metrics contract version.
    pub schema_version: String,
    /// Scanner name.
    pub tool: String,
    /// Caller-supplied corpus label. It must not be an absolute path.
    pub corpus: String,
    /// One entry per shipped rule, sorted by rule id.
    pub rules: Vec<RuleMetrics>,
    /// Aggregated totals.
    pub totals: MetricsTotals,
}

impl MetricsReport {
    /// Builds a report, sorting rules by id and computing totals.
    pub fn new(corpus: impl Into<String>, mut rules: Vec<RuleMetrics>) -> Self {
        rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        let totals = MetricsTotals {
            rules: rules.len(),
            findings: rules.iter().map(|rule| rule.findings).sum(),
            true_positives: rules.iter().map(|rule| rule.true_positives).sum(),
            false_positives: rules.iter().map(|rule| rule.false_positives).sum(),
            false_negatives: rules.iter().map(|rule| rule.false_negatives).sum(),
            true_negatives: rules.iter().map(|rule| rule.true_negatives).sum(),
            ambiguous_fixtures: rules.iter().map(|rule| rule.ambiguous_fixtures).sum(),
            runtime_micros: rules.iter().map(|rule| rule.runtime_micros).sum(),
        };
        MetricsReport {
            schema_version: METRICS_SCHEMA_VERSION.to_string(),
            tool: crate::TOOL_NAME.to_string(),
            corpus: corpus.into(),
            rules,
            totals,
        }
    }
}

impl RuleMetrics {
    /// Precision at fixture level, when a denominator exists.
    pub fn precision(&self) -> Option<f64> {
        let denominator = self.true_positives + self.false_positives;
        if denominator == 0 {
            None
        } else {
            Some(self.true_positives as f64 / denominator as f64)
        }
    }

    /// Recall at fixture level, when a denominator exists.
    pub fn recall(&self) -> Option<f64> {
        let denominator = self.true_positives + self.false_negatives;
        if denominator == 0 {
            None
        } else {
            Some(self.true_positives as f64 / denominator as f64)
        }
    }
}

/// A corpus evaluation could not be completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricsError {
    /// A manifest or fixture could not be read.
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Error message.
        message: String,
    },
    /// A manifest was not valid JSON.
    Manifest {
        /// Manifest path.
        path: PathBuf,
        /// Error message.
        message: String,
    },
    /// A fixture scan failed.
    Scan {
        /// Fixture path.
        path: PathBuf,
        /// Error message.
        message: String,
    },
}

impl fmt::Display for MetricsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetricsError::Io { path, message } => {
                write!(formatter, "{}: {message}", path.display())
            }
            MetricsError::Manifest { path, message } => {
                write!(formatter, "{}: invalid manifest: {message}", path.display())
            }
            MetricsError::Scan { path, message } => {
                write!(formatter, "{}: scan failed: {message}", path.display())
            }
        }
    }
}

impl std::error::Error for MetricsError {}

#[derive(Debug, Deserialize)]
struct CorpusManifest {
    #[serde(default)]
    fixtures: Vec<CorpusFixture>,
}

#[derive(Debug, Deserialize)]
struct CorpusFixture {
    file: String,
    #[serde(default)]
    findings: Vec<ExpectedFinding>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFinding {
    rule_id: String,
    count: usize,
}

/// Evaluates every shipped rule over the labeled corpus rooted at `corpus`.
///
/// `corpus_label` is recorded in the report instead of the filesystem path, so
/// no absolute path or username can leak into the output.
pub fn evaluate_corpus(
    corpus: &Path,
    corpus_label: &str,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> Result<MetricsReport, MetricsError> {
    let mut observations: BTreeMap<String, Vec<FixtureObservation>> = BTreeMap::new();
    let mut findings_by_rule: BTreeMap<String, usize> = BTreeMap::new();
    let mut timings: BTreeMap<String, (u64, &'static str)> = BTreeMap::new();

    for meta in registry.metadata_sorted() {
        let directory = corpus.join(meta.id);
        let manifest_path = directory.join("expected.json");
        let text = std::fs::read_to_string(&manifest_path).map_err(|error| MetricsError::Io {
            path: manifest_path.clone(),
            message: error.to_string(),
        })?;
        let manifest: CorpusManifest =
            serde_json::from_str(&text).map_err(|error| MetricsError::Manifest {
                path: manifest_path.clone(),
                message: error.to_string(),
            })?;

        for fixture in &manifest.fixtures {
            let path = directory.join(&fixture.file);
            let content = std::fs::read_to_string(&path).map_err(|error| MetricsError::Io {
                path: path.clone(),
                message: error.to_string(),
            })?;
            let outcome = if path
                .extension()
                .is_some_and(|extension| extension == "toml")
            {
                engine::scan_manifest_str("Cargo.toml", &content, config, registry).map_err(
                    |error| MetricsError::Scan {
                        path: path.clone(),
                        message: error.to_string(),
                    },
                )?
            } else {
                engine::scan_source_str(&content, &fixture.file, config, registry)
            };

            let mut actual: BTreeMap<String, usize> = BTreeMap::new();
            for finding in &outcome.findings {
                *actual.entry(finding.rule_id.clone()).or_insert(0) += 1;
            }
            for (rule_id, count) in &actual {
                *findings_by_rule.entry(rule_id.clone()).or_insert(0) += *count;
            }
            accumulate_timings(&outcome, &mut timings);

            let expected_hits: usize = fixture
                .findings
                .iter()
                .filter(|finding| finding.rule_id == meta.id)
                .map(|finding| finding.count)
                .sum();
            let label = fixture_label(&fixture.file, expected_hits);
            observations
                .entry(meta.id.to_string())
                .or_default()
                .push(FixtureObservation {
                    rule_id: meta.id.to_string(),
                    label,
                    actual_hits: actual.get(meta.id).copied().unwrap_or(0),
                });
        }
    }

    let rules = registry
        .metadata_sorted()
        .into_iter()
        .map(|meta| {
            let mut metrics = RuleMetrics {
                rule_id: meta.id.to_string(),
                title: meta.title.to_string(),
                category: meta.category.as_str().to_string(),
                findings: findings_by_rule.get(meta.id).copied().unwrap_or(0),
                true_positives: 0,
                false_positives: 0,
                false_negatives: 0,
                true_negatives: 0,
                positive_fixtures: 0,
                negative_fixtures: 0,
                ambiguous_fixtures: 0,
                runtime_micros: 0,
                status: "not_run".to_string(),
            };
            if let Some(rule_observations) = observations.get(meta.id) {
                for observation in rule_observations {
                    match observation.label {
                        FixtureLabel::Positive => {
                            metrics.positive_fixtures += 1;
                            if observation.actual_hits > 0 {
                                metrics.true_positives += 1;
                            } else {
                                metrics.false_negatives += 1;
                            }
                        }
                        FixtureLabel::Negative => {
                            metrics.negative_fixtures += 1;
                            if observation.actual_hits > 0 {
                                metrics.false_positives += 1;
                            } else {
                                metrics.true_negatives += 1;
                            }
                        }
                        FixtureLabel::Ambiguous => metrics.ambiguous_fixtures += 1,
                    }
                }
            }
            if let Some((runtime_micros, status)) = timings.get(meta.id) {
                metrics.runtime_micros = *runtime_micros;
                metrics.status = (*status).to_string();
            }
            metrics
        })
        .collect();

    Ok(MetricsReport::new(corpus_label, rules))
}

fn fixture_label(file: &str, expected_hits: usize) -> FixtureLabel {
    if file.starts_with("positive") {
        if expected_hits > 0 {
            FixtureLabel::Positive
        } else {
            FixtureLabel::Ambiguous
        }
    } else if file.starts_with("negative") {
        if expected_hits == 0 {
            FixtureLabel::Negative
        } else {
            FixtureLabel::Ambiguous
        }
    } else {
        FixtureLabel::Ambiguous
    }
}

fn accumulate_timings(outcome: &ScanOutcome, timings: &mut BTreeMap<String, (u64, &'static str)>) {
    for timing in &outcome.rule_timings {
        let elapsed = u64::try_from(timing.elapsed_micros).unwrap_or(u64::MAX);
        let entry = timings
            .entry(timing.rule_id.clone())
            .or_insert((0, RuleTimingStatus::Completed.as_str()));
        entry.0 = entry.0.saturating_add(elapsed);
        entry.1 = merge_status(entry.1, timing.status);
    }
}

fn merge_status(current: &'static str, status: RuleTimingStatus) -> &'static str {
    if current == RuleTimingStatus::Panicked.as_str() || status == RuleTimingStatus::Panicked {
        RuleTimingStatus::Panicked.as_str()
    } else if current == RuleTimingStatus::TimedOut.as_str() || status == RuleTimingStatus::TimedOut
    {
        RuleTimingStatus::TimedOut.as_str()
    } else {
        RuleTimingStatus::Completed.as_str()
    }
}

/// Renders the metrics report as stable, pretty-printed JSON.
pub fn render_json(report: &MetricsReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Renders the metrics report as deterministic Markdown.
///
/// The table is ordered by rule id. Runtime is the only measured field and the
/// document says so explicitly.
pub fn render_markdown(report: &MetricsReport) -> String {
    let mut out = String::new();
    out.push_str("# Rule Evaluation Metrics\n\n");
    out.push_str(&format!(
        "- **Schema version:** {}\n",
        report.schema_version
    ));
    out.push_str(&format!("- **Tool:** {}\n", report.tool));
    out.push_str(&format!("- **Corpus:** `{}`\n", report.corpus));
    out.push_str(&format!("- **Rules covered:** {}\n", report.totals.rules));
    out.push_str(&format!("- **Findings:** {}\n\n", report.totals.findings));

    out.push_str(
        "False positives and false negatives are fixture-level labels from the \
         corpus manifests. Ambiguous fixtures are recorded and excluded from \
         the metric totals, never guessed.\n\n",
    );
    out.push_str(
        "Runtime is measured in microseconds and is the only non-deterministic field.\n\n",
    );

    out.push_str(
        "| Rule | Findings | TP | FP | FN | TN | Positive | Negative | Ambiguous | Runtime (µs) | Status |\n",
    );
    out.push_str(
        "| ---- | -------- | -- | -- | -- | -- | -------- | -------- | --------- | ------------ | ------ |\n",
    );
    for rule in &report.rules {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            rule.rule_id,
            rule.findings,
            rule.true_positives,
            rule.false_positives,
            rule.false_negatives,
            rule.true_negatives,
            rule.positive_fixtures,
            rule.negative_fixtures,
            rule.ambiguous_fixtures,
            rule.runtime_micros,
            rule.status
        ));
    }

    out.push_str(&format!(
        "| **Total** | {} | {} | {} | {} | {} | | | {} | {} | |\n",
        report.totals.findings,
        report.totals.true_positives,
        report.totals.false_positives,
        report.totals.false_negatives,
        report.totals.true_negatives,
        report.totals.ambiguous_fixtures,
        report.totals.runtime_micros
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;

    fn rule(
        id: &str,
        findings: usize,
        true_positives: usize,
        false_positives: usize,
        false_negatives: usize,
        true_negatives: usize,
    ) -> RuleMetrics {
        RuleMetrics {
            rule_id: id.to_string(),
            title: "Example".to_string(),
            category: Category::Authorization.as_str().to_string(),
            findings,
            true_positives,
            false_positives,
            false_negatives,
            true_negatives,
            positive_fixtures: true_positives + false_negatives,
            negative_fixtures: false_positives + true_negatives,
            ambiguous_fixtures: 0,
            runtime_micros: 42,
            status: "completed".to_string(),
        }
    }

    #[test]
    fn report_sorts_rules_and_computes_totals() {
        let report = MetricsReport::new(
            "fixtures/corpus",
            vec![rule("SS-002", 3, 1, 0, 0, 2), rule("SS-001", 2, 2, 1, 0, 1)],
        );
        let ids: Vec<_> = report
            .rules
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .collect();
        assert_eq!(ids, vec!["SS-001", "SS-002"]);
        assert_eq!(report.totals.rules, 2);
        assert_eq!(report.totals.findings, 5);
        assert_eq!(report.totals.false_positives, 1);
        assert_eq!(report.totals.true_positives, 3);
    }

    #[test]
    fn precision_and_recall_handle_missing_denominators() {
        let measured = rule("SS-001", 1, 1, 1, 1, 0);
        assert_eq!(measured.precision(), Some(0.5));
        assert_eq!(measured.recall(), Some(0.5));

        let no_positives = rule("SS-002", 0, 0, 0, 0, 3);
        assert_eq!(no_positives.precision(), None);
        assert_eq!(no_positives.recall(), None);
    }

    #[test]
    fn ambiguous_fixture_labels_are_not_guessed() {
        assert_eq!(fixture_label("positive.rs", 1), FixtureLabel::Positive);
        assert_eq!(fixture_label("negative.rs", 0), FixtureLabel::Negative);
        assert_eq!(fixture_label("positive.rs", 0), FixtureLabel::Ambiguous);
        assert_eq!(fixture_label("negative.rs", 1), FixtureLabel::Ambiguous);
        assert_eq!(fixture_label("sample.rs", 1), FixtureLabel::Ambiguous);
    }
}
