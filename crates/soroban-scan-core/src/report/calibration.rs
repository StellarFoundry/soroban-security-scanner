//! Deterministic, corpus-based calibration reports.
//!
//! Calibration joins three existing sources of evidence: rule metadata, labeled
//! corpus metrics, and corpus coverage. It is advisory only. Severity is
//! impact-based and is never inferred from fixture counts. Confidence
//! recommendations are review candidates, never automatic rating changes.
//!
//! The report contains rule ids, published metadata, counts, and reasons. It
//! never includes source text, evidence, absolute paths, timing, environment
//! data, or user identifiers. Ambiguous fixtures are counted and excluded; they
//! are never guessed.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ScanConfig;
use crate::corpus::{self, CorpusCoverageRow};
use crate::registry::RuleRegistry;

use super::metrics::{self, MetricsError, MetricsReport, RuleMetrics};

/// Version of the calibration report contract.
pub const CALIBRATION_SCHEMA_VERSION: &str = "1";
/// Stable corpus label used in reports instead of a filesystem path.
pub const CALIBRATION_CORPUS_LABEL: &str = "fixtures/corpus";
/// Scope of the built-in ratings reviewed by this report.
pub const CALIBRATION_SCOPE: &str = "built-in-defaults";

/// Rating field being assessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RatingField {
    /// Rule default severity.
    Severity,
    /// Rule default confidence.
    Confidence,
}

impl RatingField {
    /// Stable lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RatingField::Severity => "severity",
            RatingField::Confidence => "confidence",
        }
    }
}

/// Outcome of a calibration assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RatingDecision {
    /// No rating change is suggested.
    NoChange,
    /// A maintainer should review the rating with the recorded evidence.
    ReviewCandidate,
    /// The corpus cannot support a confidence recommendation yet.
    InsufficientEvidence,
}

impl RatingDecision {
    /// Stable lowercase name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            RatingDecision::NoChange => "no_change",
            RatingDecision::ReviewCandidate => "review_candidate",
            RatingDecision::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

/// Advisory assessment for one rating field of one rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatingAssessment {
    /// Rating field being assessed.
    pub field: RatingField,
    /// Current built-in rating.
    pub current: String,
    /// Candidate rating for human review, never applied automatically.
    pub proposal: Option<String>,
    /// Assessment outcome.
    pub decision: RatingDecision,
    /// Deterministic, evidence-based reasons.
    pub reasons: Vec<String>,
}

/// Calibration evidence and advisory ratings for one shipped rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCalibration {
    /// Stable rule id.
    pub rule_id: String,
    /// Rule title from the catalog.
    pub title: String,
    /// Stable category name.
    pub category: String,
    /// Current built-in severity.
    pub current_severity: String,
    /// Current built-in confidence.
    pub current_confidence: String,
    /// Positive fixtures counted from the manifest.
    pub positive_fixtures: usize,
    /// Negative fixtures counted from the manifest.
    pub negative_fixtures: usize,
    /// Fixtures with an ambiguous label, excluded from rating decisions.
    pub ambiguous_fixtures: usize,
    /// Positive fixtures that triggered the rule.
    pub true_positives: usize,
    /// Negative fixtures that incorrectly triggered the rule.
    pub false_positives: usize,
    /// Positive fixtures that did not trigger the rule.
    pub false_negatives: usize,
    /// Negative fixtures that correctly did not trigger the rule.
    pub true_negatives: usize,
    /// Whether the rule satisfies the corpus coverage contract.
    pub corpus_complete: bool,
    /// Advisory severity assessment.
    pub severity_assessment: RatingAssessment,
    /// Advisory confidence assessment.
    pub confidence_assessment: RatingAssessment,
    /// Whether a maintainer should review this rule.
    pub review_required: bool,
}

/// Aggregated calibration counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationTotals {
    /// Number of shipped rules covered.
    pub rules: usize,
    /// Number of rules flagged for review.
    pub review_required: usize,
    /// Number of rules with incomplete corpus coverage.
    pub incomplete_corpus: usize,
    /// Total false positives at fixture level.
    pub false_positives: usize,
    /// Total false negatives at fixture level.
    pub false_negatives: usize,
    /// Total ambiguous fixtures.
    pub ambiguous_fixtures: usize,
}

/// A deterministic, machine-readable calibration report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationReport {
    /// Calibration contract version.
    pub schema_version: String,
    /// Scanner name.
    pub tool: String,
    /// Stable corpus label; never an absolute path.
    pub corpus: String,
    /// Ratings scope reviewed by the report.
    pub scope: String,
    /// One entry per shipped rule, sorted by rule id.
    pub rules: Vec<RuleCalibration>,
    /// Aggregated totals.
    pub totals: CalibrationTotals,
}

impl CalibrationReport {
    /// Builds a report from existing evidence, sorted and totaled deterministically.
    #[must_use]
    pub fn new(corpus: impl Into<String>, mut rules: Vec<RuleCalibration>) -> Self {
        rules.sort_by(|left, right| left.rule_id.cmp(&right.rule_id));
        let totals = CalibrationTotals {
            rules: rules.len(),
            review_required: rules.iter().filter(|rule| rule.review_required).count(),
            incomplete_corpus: rules.iter().filter(|rule| !rule.corpus_complete).count(),
            false_positives: rules.iter().map(|rule| rule.false_positives).sum(),
            false_negatives: rules.iter().map(|rule| rule.false_negatives).sum(),
            ambiguous_fixtures: rules.iter().map(|rule| rule.ambiguous_fixtures).sum(),
        };
        CalibrationReport {
            schema_version: CALIBRATION_SCHEMA_VERSION.to_string(),
            tool: crate::TOOL_NAME.to_string(),
            corpus: corpus.into(),
            scope: CALIBRATION_SCOPE.to_string(),
            rules,
            totals,
        }
    }
}

/// Builds a calibration report from metrics, coverage, and registry metadata.
///
/// Every shipped rule gets a row even when evidence is missing; missing
/// evidence is recorded as insufficient rather than guessed.
#[must_use]
pub fn build_report(
    metrics: &MetricsReport,
    coverage: &[CorpusCoverageRow],
    registry: &RuleRegistry,
) -> CalibrationReport {
    let metrics_by_id: BTreeMap<&str, &RuleMetrics> = metrics
        .rules
        .iter()
        .map(|row| (row.rule_id.as_str(), row))
        .collect();
    let coverage_by_id: BTreeMap<&str, &CorpusCoverageRow> = coverage
        .iter()
        .map(|row| (row.rule_id.as_str(), row))
        .collect();

    let rules = registry
        .metadata_sorted()
        .into_iter()
        .map(|meta| {
            let metric = metrics_by_id.get(meta.id).copied();
            let covered = coverage_by_id.get(meta.id).copied();
            let corpus_complete = covered.is_some_and(CorpusCoverageRow::complete);
            let ambiguous_fixtures = metric.map_or(0, |row| row.ambiguous_fixtures);
            let false_positives = metric.map_or(0, |row| row.false_positives);
            let false_negatives = metric.map_or(0, |row| row.false_negatives);

            let severity_assessment = RatingAssessment {
                field: RatingField::Severity,
                current: meta.default_severity.as_str().to_string(),
                proposal: None,
                decision: RatingDecision::NoChange,
                reasons: vec![
                    "severity measures impact; corpus counts measure detection evidence only"
                        .to_string(),
                    "any severity change requires a human impact justification in the PR"
                        .to_string(),
                ],
            };
            let confidence_assessment = assess_confidence(
                meta.default_confidence.as_str(),
                corpus_complete,
                covered,
                metric,
            );
            let review_required = severity_assessment.decision == RatingDecision::ReviewCandidate
                || confidence_assessment.decision != RatingDecision::NoChange;

            RuleCalibration {
                rule_id: meta.id.to_string(),
                title: meta.title.to_string(),
                category: meta.category.as_str().to_string(),
                current_severity: severity_assessment.current.clone(),
                current_confidence: confidence_assessment.current.clone(),
                positive_fixtures: metric.map_or(0, |row| row.positive_fixtures),
                negative_fixtures: metric.map_or(0, |row| row.negative_fixtures),
                ambiguous_fixtures,
                true_positives: metric.map_or(0, |row| row.true_positives),
                false_positives,
                false_negatives,
                true_negatives: metric.map_or(0, |row| row.true_negatives),
                corpus_complete,
                severity_assessment,
                confidence_assessment,
                review_required,
            }
        })
        .collect();

    CalibrationReport::new(metrics.corpus.clone(), rules)
}

fn assess_confidence(
    current: &'static str,
    corpus_complete: bool,
    covered: Option<&CorpusCoverageRow>,
    metric: Option<&RuleMetrics>,
) -> RatingAssessment {
    let mut reasons = Vec::new();
    if !corpus_complete {
        reasons.push("corpus coverage contract is incomplete".to_string());
        if let Some(covered) = covered {
            if covered.positives == 0 {
                reasons.push("no positive fixture is present".to_string());
            }
            if covered.negatives < 3 {
                reasons.push("fewer than three negative fixtures are present".to_string());
            }
            if !covered.documented {
                reasons.push("detector documentation is missing".to_string());
            }
            if !covered.must_trigger {
                reasons.push("must-trigger sample is missing".to_string());
            }
        } else {
            reasons.push("no coverage row is present".to_string());
        }
        return RatingAssessment {
            field: RatingField::Confidence,
            current: current.to_string(),
            proposal: None,
            decision: RatingDecision::InsufficientEvidence,
            reasons,
        };
    }

    let ambiguous = metric.map_or(0, |row| row.ambiguous_fixtures);
    let false_positives = metric.map_or(0, |row| row.false_positives);
    let false_negatives = metric.map_or(0, |row| row.false_negatives);
    if ambiguous > 0 {
        reasons.push(format!(
            "{ambiguous} ambiguous fixture(s) were excluded and confidence was not raised"
        ));
    }
    if false_negatives > 0 {
        reasons.push(format!(
            "{false_negatives} false negative fixture(s) record a detection gap"
        ));
    }
    if false_positives > 0 {
        reasons.push(format!(
            "{false_positives} false positive fixture(s) warrant confidence review"
        ));
        if current != "low" {
            return RatingAssessment {
                field: RatingField::Confidence,
                current: current.to_string(),
                proposal: Some("low".to_string()),
                decision: RatingDecision::ReviewCandidate,
                reasons,
            };
        }
        reasons.push("confidence is already low; no change is proposed".to_string());
        return RatingAssessment {
            field: RatingField::Confidence,
            current: current.to_string(),
            proposal: None,
            decision: RatingDecision::NoChange,
            reasons,
        };
    }

    if ambiguous == 0 && false_negatives == 0 && current != "high" {
        reasons.push(
            "curated corpus shows no fixture-level errors; this is limited evidence and requires review before any change"
                .to_string(),
        );
        return RatingAssessment {
            field: RatingField::Confidence,
            current: current.to_string(),
            proposal: Some("high".to_string()),
            decision: RatingDecision::ReviewCandidate,
            reasons,
        };
    }

    if reasons.is_empty() {
        reasons.push("no fixture-level evidence warrants a confidence change".to_string());
    }
    RatingAssessment {
        field: RatingField::Confidence,
        current: current.to_string(),
        proposal: None,
        decision: RatingDecision::NoChange,
        reasons,
    }
}

/// Evaluates corpus calibration rooted at `root` for every rule in `registry`.
pub fn evaluate_calibration(
    root: &Path,
    registry: &RuleRegistry,
) -> Result<CalibrationReport, MetricsError> {
    let corpus_dir = root.join("fixtures").join("corpus");
    let metrics_report = metrics::evaluate_corpus(
        &corpus_dir,
        CALIBRATION_CORPUS_LABEL,
        &ScanConfig::default(),
        registry,
    )?;
    let coverage = corpus::coverage(root, registry);
    Ok(build_report(&metrics_report, &coverage, registry))
}

/// Renders the calibration report as stable, pretty-printed JSON.
pub fn render_json(report: &CalibrationReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

fn md_cell(value: &str) -> String {
    value.replace('|', "\\|").replace(['\r', '\n'], " ")
}

/// Renders the aggregate calibration report as deterministic Markdown.
#[must_use]
pub fn render_markdown(report: &CalibrationReport) -> String {
    let mut out = String::new();
    out.push_str("# Rule Calibration Report\n\n");
    out.push_str(&format!(
        "- **Schema version:** {}\n",
        report.schema_version
    ));
    out.push_str(&format!("- **Tool:** {}\n", report.tool));
    out.push_str(&format!("- **Corpus:** `{}`\n", report.corpus));
    out.push_str(&format!("- **Scope:** `{}`\n", report.scope));
    out.push_str(&format!("- **Rules covered:** {}\n", report.totals.rules));
    out.push_str(&format!(
        "- **Rules flagged for review:** {}\n",
        report.totals.review_required
    ));
    out.push_str(&format!(
        "- **Rules with incomplete corpus coverage:** {}\n\n",
        report.totals.incomplete_corpus
    ));

    out.push_str(
        "This report is advisory. It does not change severity or confidence. \
         Severity is impact-based and is never derived from fixture counts. \
         Confidence candidates require maintainer review with corpus evidence. \
         Ambiguous fixtures are recorded and excluded, never guessed.\n\n",
    );

    out.push_str(
        "| Rule | Title | Severity | Confidence | TP | FP | FN | TN | Ambiguous | Corpus | Review |\n\
         | ---- | ----- | -------- | ---------- | -- | -- | -- | -- | --------- | ------ | ------ |\n",
    );
    for rule in &report.rules {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            md_cell(&rule.rule_id),
            md_cell(&rule.title),
            md_cell(&rule.current_severity),
            md_cell(&rule.current_confidence),
            rule.true_positives,
            rule.false_positives,
            rule.false_negatives,
            rule.true_negatives,
            rule.ambiguous_fixtures,
            if rule.corpus_complete {
                "complete"
            } else {
                "incomplete"
            },
            if rule.review_required { "yes" } else { "no" },
        ));
    }

    out.push_str("\n## Review candidates\n\n");
    let candidates: Vec<&RuleCalibration> = report
        .rules
        .iter()
        .filter(|rule| rule.review_required)
        .collect();
    if candidates.is_empty() {
        out.push_str("No rules are currently flagged for review.\n");
    } else {
        for rule in candidates {
            out.push_str(&format!(
                "### {} — {}\n\n",
                rule.rule_id,
                md_cell(&rule.title)
            ));
            for assessment in [&rule.severity_assessment, &rule.confidence_assessment] {
                out.push_str(&format!(
                    "- **{}:** {} ({})",
                    assessment.field.as_str(),
                    assessment.decision.as_str(),
                    assessment.current
                ));
                if let Some(proposal) = &assessment.proposal {
                    out.push_str(&format!("; candidate `{proposal}`"));
                }
                out.push('\n');
                for reason in &assessment.reasons {
                    out.push_str(&format!("  - {}\n", md_cell(reason)));
                }
            }
            out.push('\n');
        }
    }

    out
}

/// Renders one reviewable Markdown report per rule.
#[must_use]
pub fn render_rule_markdown(rule: &RuleCalibration) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# {} — {}\n\n",
        rule.rule_id,
        md_cell(&rule.title)
    ));
    out.push_str(&format!("- **Category:** `{}`\n", md_cell(&rule.category)));
    out.push_str(&format!(
        "- **Current rating:** {} severity / {} confidence\n",
        md_cell(&rule.current_severity),
        md_cell(&rule.current_confidence)
    ));
    out.push_str(&format!(
        "- **Corpus coverage:** {}\n\n",
        if rule.corpus_complete {
            "complete"
        } else {
            "incomplete"
        }
    ));

    out.push_str(
        "| Positive fixtures | Negative fixtures | Ambiguous | TP | FP | FN | TN |\n\
         | ----------------- | ----------------- | --------- | -- | -- | -- | -- |\n",
    );
    out.push_str(&format!(
        "| {} | {} | {} | {} | {} | {} | {} |\n\n",
        rule.positive_fixtures,
        rule.negative_fixtures,
        rule.ambiguous_fixtures,
        rule.true_positives,
        rule.false_positives,
        rule.false_negatives,
        rule.true_negatives
    ));

    for assessment in [&rule.severity_assessment, &rule.confidence_assessment] {
        out.push_str(&format!("## {} assessment\n\n", assessment.field.as_str()));
        out.push_str(&format!(
            "- **Decision:** {}\n",
            assessment.decision.as_str()
        ));
        out.push_str(&format!("- **Current:** {}\n", assessment.current));
        out.push_str(&format!(
            "- **Candidate:** {}\n\n",
            assessment
                .proposal
                .as_deref()
                .map_or_else(|| "none".to_string(), |value| format!("`{value}`"))
        ));
        out.push_str("Reasons:\n\n");
        for reason in &assessment.reasons {
            out.push_str(&format!("- {}\n", md_cell(reason)));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "**Review required:** {}\n\n",
        if rule.review_required { "yes" } else { "no" }
    ));
    out.push_str(
        "This report is advisory. It does not apply rating changes. Any change \
         must be justified in the PR with corpus evidence and impact analysis. \
         See [calibration methodology](calibration.md) for the full policy.\n",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::metrics::MetricsTotals;

    fn metric(rule_id: &str) -> RuleMetrics {
        RuleMetrics {
            rule_id: rule_id.to_string(),
            title: format!("Rule {rule_id}"),
            category: "authorization".to_string(),
            findings: 0,
            true_positives: 2,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 3,
            positive_fixtures: 2,
            negative_fixtures: 3,
            ambiguous_fixtures: 0,
            runtime_micros: 999,
            status: "completed".to_string(),
        }
    }

    fn complete_coverage(rule_id: &str) -> CorpusCoverageRow {
        CorpusCoverageRow {
            rule_id: rule_id.to_string(),
            positives: 2,
            negatives: 3,
            documented: true,
            must_trigger: true,
        }
    }

    fn assessment(
        field: RatingField,
        decision: RatingDecision,
        proposal: Option<&str>,
    ) -> RatingAssessment {
        RatingAssessment {
            field,
            current: "medium".to_string(),
            proposal: proposal.map(str::to_string),
            decision,
            reasons: vec!["fixture-level evidence from the labeled corpus".to_string()],
        }
    }

    fn sample_row(id: &str, review: bool) -> RuleCalibration {
        RuleCalibration {
            rule_id: id.to_string(),
            title: format!("Rule {id}"),
            category: "authorization".to_string(),
            current_severity: "medium".to_string(),
            current_confidence: "medium".to_string(),
            positive_fixtures: 1,
            negative_fixtures: 3,
            ambiguous_fixtures: 0,
            true_positives: 1,
            false_positives: 0,
            false_negatives: 0,
            true_negatives: 3,
            corpus_complete: true,
            severity_assessment: assessment(RatingField::Severity, RatingDecision::NoChange, None),
            confidence_assessment: assessment(
                RatingField::Confidence,
                if review {
                    RatingDecision::ReviewCandidate
                } else {
                    RatingDecision::NoChange
                },
                if review { Some("high") } else { None },
            ),
            review_required: review,
        }
    }

    fn sample_report() -> CalibrationReport {
        CalibrationReport::new(
            CALIBRATION_CORPUS_LABEL,
            vec![sample_row("SS-002", false), sample_row("SS-001", true)],
        )
    }

    #[test]
    fn report_sorts_rules_and_computes_totals() {
        let report = sample_report();
        assert_eq!(report.rules[0].rule_id, "SS-001");
        assert_eq!(report.rules[1].rule_id, "SS-002");
        assert_eq!(report.totals.rules, 2);
        assert_eq!(report.totals.review_required, 1);
        assert_eq!(report.totals.incomplete_corpus, 0);
    }

    #[test]
    fn build_report_covers_every_shipped_rule_without_changing_severity() {
        let registry = RuleRegistry::with_default_rules();
        let ids: Vec<String> = registry
            .metadata_sorted()
            .iter()
            .map(|meta| meta.id.to_string())
            .collect();
        let metrics_report = MetricsReport::new(
            CALIBRATION_CORPUS_LABEL,
            ids.iter().map(|id| metric(id)).collect(),
        );
        let coverage: Vec<CorpusCoverageRow> = ids.iter().map(|id| complete_coverage(id)).collect();

        let report = build_report(&metrics_report, &coverage, &registry);
        let actual: Vec<&str> = report
            .rules
            .iter()
            .map(|rule| rule.rule_id.as_str())
            .collect();
        let expected: Vec<&str> = ids.iter().map(String::as_str).collect();
        assert_eq!(actual, expected);
        for rule in &report.rules {
            assert_eq!(rule.severity_assessment.decision, RatingDecision::NoChange);
            assert_eq!(rule.severity_assessment.proposal, None);
            assert_eq!(rule.current_severity, rule.severity_assessment.current);
            let serialized = serde_json::to_string(rule).expect("serialize rule calibration");
            assert!(!serialized.contains("runtime_micros"));
        }
    }

    #[test]
    fn false_positives_produce_a_confidence_review_candidate() {
        let registry = RuleRegistry::with_default_rules();
        let ids: Vec<String> = registry
            .metadata_sorted()
            .iter()
            .map(|meta| meta.id.to_string())
            .collect();
        let mut rows: Vec<RuleMetrics> = ids.iter().map(|id| metric(id)).collect();
        rows[0].false_positives = 2;
        rows[0].true_positives = 1;
        let metrics_report = MetricsReport::new(CALIBRATION_CORPUS_LABEL, rows);
        let coverage: Vec<CorpusCoverageRow> = ids.iter().map(|id| complete_coverage(id)).collect();

        let report = build_report(&metrics_report, &coverage, &registry);
        let target = &report.rules[0];
        assert_eq!(target.false_positives, 2);
        assert_eq!(
            target.confidence_assessment.decision,
            RatingDecision::ReviewCandidate
        );
        assert_eq!(
            target.confidence_assessment.proposal.as_deref(),
            Some("low")
        );
        assert!(target
            .confidence_assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("2 false positive")));
    }

    #[test]
    fn incomplete_corpus_does_not_raise_confidence() {
        let registry = RuleRegistry::with_default_rules();
        let ids: Vec<String> = registry
            .metadata_sorted()
            .iter()
            .map(|meta| meta.id.to_string())
            .collect();
        let metrics_report = MetricsReport::new(
            CALIBRATION_CORPUS_LABEL,
            ids.iter().map(|id| metric(id)).collect(),
        );
        let mut coverage: Vec<CorpusCoverageRow> =
            ids.iter().map(|id| complete_coverage(id)).collect();
        coverage[0].must_trigger = false;

        let report = build_report(&metrics_report, &coverage, &registry);
        let assessment = &report.rules[0].confidence_assessment;
        assert_eq!(assessment.decision, RatingDecision::InsufficientEvidence);
        assert_eq!(assessment.proposal, None);
        assert!(assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("must-trigger")));
    }

    #[test]
    fn ambiguous_fixtures_are_recorded_and_never_promote_confidence() {
        let registry = RuleRegistry::with_default_rules();
        let ids: Vec<String> = registry
            .metadata_sorted()
            .iter()
            .map(|meta| meta.id.to_string())
            .collect();
        let mut rows: Vec<RuleMetrics> = ids.iter().map(|id| metric(id)).collect();
        rows[0].ambiguous_fixtures = 3;
        let metrics_report = MetricsReport::new(CALIBRATION_CORPUS_LABEL, rows);
        let coverage: Vec<CorpusCoverageRow> = ids.iter().map(|id| complete_coverage(id)).collect();

        let report = build_report(&metrics_report, &coverage, &registry);
        let target = &report.rules[0];
        assert_eq!(target.ambiguous_fixtures, 3);
        assert_eq!(target.confidence_assessment.proposal, None);
        assert!(target
            .confidence_assessment
            .reasons
            .iter()
            .any(|reason| reason.contains("3 ambiguous fixture")));
    }

    #[test]
    fn renderers_are_byte_stable_and_contain_no_timing_or_absolute_paths() {
        let report = sample_report();
        let first_json = render_json(&report).expect("render JSON");
        let second_json = render_json(&report).expect("render JSON");
        let first_markdown = render_markdown(&report);
        let second_markdown = render_markdown(&report);
        assert_eq!(first_json, second_json);
        assert_eq!(first_markdown, second_markdown);
        for rendered in [&first_json, &first_markdown] {
            assert!(!rendered.contains("runtime_micros"));
            assert!(!rendered.contains("C:\\"));
            assert!(!rendered.contains("/home/"));
        }
        assert!(render_rule_markdown(&report.rules[0]).contains("Review required"));
    }

    #[test]
    fn totals_ignore_metrics_totals_for_advisory_counts() {
        let totals = MetricsTotals {
            rules: 99,
            runtime_micros: 1234,
            ..MetricsTotals::default()
        };
        assert_eq!(totals.rules, 99);
        let report = sample_report();
        assert_eq!(report.totals.rules, 2);
        assert!(!render_markdown(&report).contains("1234"));
    }
}
