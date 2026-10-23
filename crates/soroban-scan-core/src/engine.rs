//! The scanner pipeline.
//!
//! The engine runs enabled rules over an immutable [`AnalysisContext`],
//! validates every finding against the scan root and known source files,
//! applies configuration overrides and filters, de-duplicates, and sorts the
//! result deterministically.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use globset::Glob;
use serde::Serialize;

use crate::config::{ScanConfig, SuppressionRule};
use crate::context::AnalysisContext;
use crate::error::ScanError;
use crate::finding::Finding;
use crate::model::{Diagnostic, DiagnosticCode, Project, ProjectKind, SorobanInfo};
use crate::project::{self, LoadedProject};
use crate::registry::RuleRegistry;
use crate::suppression::Suppression;

/// Statistics about a scan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanStats {
    /// Number of rules executed.
    pub rules_run: usize,
    /// Number of rules skipped by configuration.
    pub rules_skipped: usize,
    /// Number of rules that panicked and were isolated.
    pub rules_failed: usize,
    /// Number of rules abandoned after exceeding their execution budget.
    pub rules_timed_out: usize,
    /// Number of source files analyzed.
    pub files_analyzed: usize,
    /// Number of source files that parsed successfully.
    pub files_parsed: usize,
    /// Number of source files that failed to parse.
    pub files_failed: usize,
    /// Number of discovered source files skipped before parsing.
    pub files_skipped: usize,
    /// Findings produced before validation/filtering.
    pub findings_raw: usize,
    /// Findings dropped because they referenced an unknown file.
    pub findings_rejected: usize,
    /// Inline suppression directives detected in the analyzed sources.
    pub suppressions_detected: usize,
    /// Findings excluded from the gate by any suppression.
    pub findings_suppressed: usize,
    /// Findings excluded from the gate by a configured suppression.
    pub findings_suppressed_by_config: usize,
    /// Configured suppression entries present in the effective configuration.
    pub config_suppressions_detected: usize,
    /// Configured suppression entries whose path matched at least one finding.
    pub config_suppressions_matched: usize,
    /// Configured suppression entries that suppressed at least one finding.
    pub config_suppressions_applied: usize,
    /// Source files marked as generated and still analyzed.
    pub generated_files_marked: usize,
    /// Source files excluded because they are generated.
    pub generated_files_excluded: usize,
    /// Gate findings grouped by stable category name, sorted deterministically.
    pub findings_by_category: BTreeMap<String, usize>,
}

/// Outcome of one rule execution for the opt-in timing breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTimingStatus {
    /// The rule completed normally.
    Completed,
    /// The rule exceeded its configured time budget.
    TimedOut,
    /// The rule panicked and was isolated.
    Panicked,
}

impl RuleTimingStatus {
    /// Stable lowercase label used in `--timings` output.
    pub fn as_str(self) -> &'static str {
        match self {
            RuleTimingStatus::Completed => "completed",
            RuleTimingStatus::TimedOut => "timed_out",
            RuleTimingStatus::Panicked => "panicked",
        }
    }
}

/// Wall-clock time spent in one rule.
///
/// Timings are presentation-only metadata for `--timings`. They are never
/// included in JSON/SARIF/Markdown reports and never influence findings,
/// ordering, fingerprints or the exit gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTiming {
    /// Rule id (for example `SS-001`).
    pub rule_id: String,
    /// Elapsed microseconds, summed across roots when merging outcomes.
    pub elapsed_micros: u128,
    /// How the rule finished.
    pub status: RuleTimingStatus,
}

impl RuleTiming {
    /// Elapsed time in milliseconds.
    pub fn elapsed_ms(&self) -> f64 {
        self.elapsed_micros as f64 / 1_000.0
    }
}

/// How many findings were shown after an explicit report limit.
///
/// Truncation only affects presentation: the failure gate is evaluated against
/// every finding before this record is attached. The counts make the omitted
/// findings machine-readable, so a bounded report can never hide that it was
/// truncated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FindingTruncation {
    /// Number of findings included in the report.
    pub shown: usize,
    /// Number of findings before truncation.
    pub total: usize,
    /// Number of findings omitted from the report.
    pub omitted: usize,
}

/// The full result of a scan.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    /// Project metadata.
    pub project: Project,
    /// Final findings, sorted and de-duplicated.
    ///
    /// Findings suppressed by an inline directive are **not** included here;
    /// they are reported in [`ScanOutcome::suppressed`] instead.
    pub findings: Vec<Finding>,
    /// Diagnostics (project + pipeline).
    pub diagnostics: Vec<Diagnostic>,
    /// Scan statistics.
    pub stats: ScanStats,
    /// Effective configuration used for this scan.
    ///
    /// Recorded so a JSON report is reproducible and auditable. It contains no
    /// environment data or secrets.
    pub config: ScanConfig,
    /// Inline suppression directives detected during the scan.
    ///
    /// Every detected directive is listed, including directives that matched no
    /// finding, so suppression usage stays auditable.
    pub suppressions: Vec<Suppression>,
    /// Findings excluded from the gate by any suppression.
    pub suppressed: Vec<SuppressedFinding>,
    /// Audit records for every configured suppression, including unused ones.
    pub config_suppressions: Vec<ConfigSuppressionReport>,
    /// Set when the caller bounded the number of reported findings.
    ///
    /// `None` means the report contains every finding. The gate is always
    /// evaluated before truncation, so this field never changes the exit code.
    pub truncation: Option<FindingTruncation>,
    /// Per-rule wall-clock timings, in registration order (or rule id order
    /// after merging roots). Presentation-only; never serialized into reports.
    pub rule_timings: Vec<RuleTiming>,
}

impl ScanOutcome {
    /// Bounds the reported findings to `max`, preserving their sorted order.
    ///
    /// The exit gate must be computed before calling this method. A limit that
    /// is absent or not smaller than the finding count leaves the outcome
    /// unchanged and clears any previous truncation record.
    pub fn truncate_findings(&mut self, max: Option<usize>) {
        self.truncation = None;
        let total = self.findings.len();
        if let Some(max) = max {
            if total > max {
                self.findings.truncate(max);
                self.truncation = Some(FindingTruncation {
                    shown: max,
                    total,
                    omitted: total - max,
                });
            }
        }
    }
}

/// Where a suppression came from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionSource {
    /// An inline `soroban-scan: ignore` directive.
    #[default]
    Inline,
    /// A `[[suppressions]]` entry from configuration.
    Config,
}

impl SuppressionSource {
    fn is_inline(&self) -> bool {
        *self == SuppressionSource::Inline
    }
}

/// The directive or configuration entry that suppressed a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppressionInfo {
    /// Root-relative, forward-slash file used for the suppression.
    pub file: String,
    /// 1-based line used for the suppression.
    pub line: usize,
    /// Rule targets (for example `SS-001,SS-002`, or `all`).
    pub rules: String,
    /// Reason supplied by the directive or configuration, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Suppression source.
    #[serde(default, skip_serializing_if = "SuppressionSource::is_inline")]
    pub source: SuppressionSource,
    /// Configured path glob, when `source` is `config`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Audit record for one configured suppression entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfigSuppressionReport {
    /// Configured relative path glob.
    pub path: String,
    /// Configured rule id or `all`.
    pub rule: String,
    /// Optional reason.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Number of findings whose path matched this glob, regardless of rule.
    pub matched: usize,
    /// Number of findings this entry removed from the gate.
    pub findings_suppressed: usize,
    /// True when at least one finding was suppressed.
    pub applied: bool,
}

/// A finding excluded from the gate by an inline suppression directive.
///
/// Suppressed findings are still reported — with the directive and the reason
/// that suppressed them — so a suppression can never hide a finding silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppressedFinding {
    /// The suppressed finding, serialized inline.
    #[serde(flatten)]
    pub finding: Finding,
    /// Directive that suppressed the finding.
    pub suppression: SuppressionInfo,
}

/// Normalizes a relative path to forward slashes without a leading `./`.
fn normalize_rel(path: &Path) -> String {
    let s = path.to_string_lossy().replace('\\', "/");
    s.strip_prefix("./").unwrap_or(&s).to_string()
}

/// Inclusive line range used for overlap checks.
fn finding_span(finding: &Finding) -> (usize, usize) {
    let start = finding.location.line;
    let end = finding.location.end_line.unwrap_or(start).max(start);
    (start, end)
}

/// Inclusive column range, or the whole line when the column is unknown.
fn finding_column_span(finding: &Finding) -> (usize, usize) {
    match finding.location.column {
        None => (0, usize::MAX),
        Some(start) => {
            let end = finding.location.end_column.unwrap_or(start).max(start);
            (start, end)
        }
    }
}

/// Whether two findings occupy overlapping inclusive line/column ranges.
///
/// Multi-line findings overlap by line range. Two single-line findings must
/// also have overlapping column ranges, so distinct issues on the same line
/// (for example two hardcoded addresses) are not merged.
fn spans_overlap(left: &Finding, right: &Finding) -> bool {
    let (left_start, left_end) = finding_span(left);
    let (right_start, right_end) = finding_span(right);
    if !(left_start <= right_end && right_start <= left_end) {
        return false;
    }
    if left_start == left_end && right_start == right_end {
        let (left_column_start, left_column_end) = finding_column_span(left);
        let (right_column_start, right_column_end) = finding_column_span(right);
        return left_column_start <= right_column_end && right_column_start <= left_column_end;
    }
    true
}

/// Whether `candidate` should replace `current` under the overlap policy.
///
/// The earliest start wins; at the same start the narrower span is more
/// specific; then the smaller column; finally the lexicographically smaller
/// fingerprint keeps the result deterministic.
fn is_more_specific(candidate: &Finding, current: &Finding) -> bool {
    let (candidate_start, candidate_end) = finding_span(candidate);
    let (current_start, current_end) = finding_span(current);
    if candidate_start != current_start {
        return candidate_start < current_start;
    }
    let candidate_width = candidate_end - candidate_start;
    let current_width = current_end - current_start;
    if candidate_width != current_width {
        return candidate_width < current_width;
    }
    let candidate_column = candidate.location.column.unwrap_or(0);
    let current_column = current.location.column.unwrap_or(0);
    if candidate_column != current_column {
        return candidate_column < current_column;
    }
    candidate.fingerprint < current.fingerprint
}

/// Collapses overlapping findings from the same rule and file.
///
/// The documented policy is: findings with the same `rule_id` and normalized
/// file whose inclusive line ranges overlap describe the same issue. Exactly
/// one survives, preferring the earliest start, then the narrowest span, then
/// the smallest column, then the smallest fingerprint. Adjacent ranges (for
/// example `1..=2` and `3..=4`) do **not** overlap. Findings from different
/// rules or files are never merged.
fn deduplicate_overlapping(findings: &mut Vec<Finding>) {
    let mut groups: BTreeMap<(String, String), Vec<Finding>> = BTreeMap::new();
    for finding in findings.drain(..) {
        let key = (
            finding.rule_id.clone(),
            normalize_rel(&finding.location.file),
        );
        groups.entry(key).or_default().push(finding);
    }

    let mut kept = Vec::new();
    for (_, group) in groups {
        let mut selected: Vec<Finding> = Vec::new();
        for finding in group {
            if let Some(index) = selected
                .iter()
                .position(|existing| spans_overlap(existing, &finding))
            {
                if is_more_specific(&finding, &selected[index]) {
                    selected[index] = finding;
                }
            } else {
                selected.push(finding);
            }
        }
        kept.extend(selected);
    }

    kept.sort_by_key(Finding::sort_key);
    *findings = kept;
}

/// Returns true if `path` is a safe, relative path with no traversal.
fn is_safe_relative(path: &Path) -> bool {
    if path.is_absolute() {
        return false;
    }
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => return false,
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return false,
            _ => {}
        }
    }
    !path.as_os_str().is_empty()
}

/// Returns diagnostics for severity or confidence overrides that cannot apply.
///
/// An override is ineffective when its rule id is unknown, the rule is disabled
/// by default, or the rule is disabled by the effective configuration. The
/// result is deterministic and contains one diagnostic per rule id.
pub fn override_diagnostics(config: &ScanConfig, registry: &RuleRegistry) -> Vec<Diagnostic> {
    let mut kinds: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for id in config.rules.severity_overrides.keys() {
        kinds.entry(id.as_str()).or_default().push("severity");
    }
    for id in config.rules.confidence_overrides.keys() {
        kinds.entry(id.as_str()).or_default().push("confidence");
    }

    kinds
        .into_iter()
        .filter_map(|(id, kinds)| {
            let reason = match registry.by_id(id) {
                None => "unknown rule id",
                Some(rule) if !rule.enabled_by_default() => "rule is disabled by default",
                Some(rule) => {
                    let meta = rule.metadata();
                    if config.rules.is_rule_enabled(meta.id, meta.category) {
                        return None;
                    }
                    "rule is disabled by configuration"
                }
            };
            Some(Diagnostic::warning(
                DiagnosticCode::IneffectiveOverride,
                format!(
                    "{} override for {id} has no effect: {reason}",
                    kinds.join(" and ")
                ),
                None,
            ))
        })
        .collect()
}

struct CompiledConfigSuppression {
    report: ConfigSuppressionReport,
    matcher: Option<globset::GlobMatcher>,
    rule: String,
    path: String,
    reason: Option<String>,
}

impl CompiledConfigSuppression {
    fn rule_matches(&self, rule_id: &str) -> bool {
        self.rule
            .eq_ignore_ascii_case(crate::config::ALL_SUPPRESSION_RULES)
            || self.rule.eq_ignore_ascii_case(rule_id)
    }
}

/// Compiles configured suppressions deterministically.
///
/// Invalid entries are never dropped silently: they emit a `CONFIG-002`
/// diagnostic and remain visible in the audit report with no matches.
fn compile_config_suppressions(
    config: &ScanConfig,
    diagnostics: &mut Vec<Diagnostic>,
) -> Vec<CompiledConfigSuppression> {
    let mut indexed: Vec<&SuppressionRule> = config.suppressions.iter().collect();
    indexed.sort_by(|a, b| {
        (
            a.path.trim(),
            a.rule_label(),
            a.reason.as_deref().unwrap_or_default(),
        )
            .cmp(&(
                b.path.trim(),
                b.rule_label(),
                b.reason.as_deref().unwrap_or_default(),
            ))
    });

    indexed
        .into_iter()
        .map(|rule| {
            let reason = rule
                .reason
                .as_ref()
                .map(|reason| reason.trim().to_string())
                .filter(|reason| !reason.is_empty());
            let (matcher, rule_text, path) = match rule.validate() {
                Ok(()) => {
                    let matcher = Glob::new(rule.path.trim())
                        .ok()
                        .map(|glob| glob.compile_matcher());
                    (matcher, rule.rule_label(), rule.path.trim().to_string())
                }
                Err(error) => {
                    diagnostics.push(Diagnostic::warning(
                        DiagnosticCode::InvalidSuppression,
                        format!(
                            "configured suppression for '{}' is invalid and was not applied: {error}",
                            rule.path
                        ),
                        None,
                    ));
                    (None, rule.rule_label(), rule.path.trim().to_string())
                }
            };
            CompiledConfigSuppression {
                report: ConfigSuppressionReport {
                    path: path.clone(),
                    rule: rule_text.clone(),
                    reason: reason.clone(),
                    matched: 0,
                    findings_suppressed: 0,
                    applied: false,
                },
                matcher,
                rule: rule_text,
                path,
                reason,
            }
        })
        .collect()
}

/// Runs the scanner over a loaded project.
pub fn scan(loaded: &LoadedProject, registry: &RuleRegistry, config: &ScanConfig) -> ScanOutcome {
    let ctx = AnalysisContext::new(
        &loaded.project,
        &loaded.sources,
        &config.minimum_soroban_sdk,
    );
    let mut known: BTreeSet<String> = loaded
        .sources
        .iter()
        .map(|s| normalize_rel(&ctx.relative_path(&s.path)))
        .collect();
    known.extend(
        loaded
            .project
            .manifests
            .iter()
            .map(|manifest| normalize_rel(&ctx.relative_path(&manifest.path))),
    );

    let mut diagnostics = loaded.project.diagnostics.clone();
    diagnostics.extend(override_diagnostics(config, registry));
    let mut findings: Vec<Finding> = Vec::new();
    let mut stats = ScanStats {
        files_analyzed: loaded.sources.len(),
        files_parsed: loaded
            .sources
            .iter()
            .filter(|source| source.is_parsed())
            .count(),
        files_skipped: loaded
            .project
            .source_files
            .saturating_sub(loaded.sources.len()),
        generated_files_marked: loaded
            .sources
            .iter()
            .filter(|source| source.is_generated())
            .count(),
        generated_files_excluded: loaded.generated_files_excluded,
        ..ScanStats::default()
    };
    stats.files_failed = stats.files_analyzed - stats.files_parsed;

    let budget = config.rules.rule_time_budget_ms.map(Duration::from_millis);
    let mut rule_timings: Vec<RuleTiming> = Vec::new();

    // Execution order is explicitly by rule id, independent of registration
    // order. This keeps diagnostics, timings, and any future early-exit
    // behavior deterministic even before findings are sorted (#106).
    let mut rules: Vec<&dyn crate::rule::Rule> =
        registry.rules().iter().map(|rule| rule.as_ref()).collect();
    rules.sort_by_key(|rule| rule.metadata().id);

    for rule in rules {
        let meta = rule.metadata();
        if !rule.enabled_by_default() || !config.rules.is_rule_enabled(meta.id, meta.category) {
            stats.rules_skipped += 1;
            continue;
        }
        stats.rules_run += 1;

        let started = Instant::now();
        let mut rule_findings = Vec::new();
        let result = catch_unwind(AssertUnwindSafe(|| rule.analyze(&ctx, &mut rule_findings)));
        let elapsed = started.elapsed();
        match result {
            Ok(()) => {
                if let Some(limit) = budget {
                    if elapsed > limit {
                        // Rust cannot preempt a running rule and the parsed AST
                        // is not thread-safe, so the budget is best-effort:
                        // discard everything the rule produced after overrunning
                        // and report the overrun.
                        stats.rules_timed_out += 1;
                        rule_timings.push(RuleTiming {
                            rule_id: meta.id.to_string(),
                            elapsed_micros: elapsed.as_micros(),
                            status: RuleTimingStatus::TimedOut,
                        });
                        diagnostics.push(Diagnostic::warning(
                            DiagnosticCode::RuleTimeBudgetExceeded,
                            format!(
                                "rule {} exceeded its {} ms execution budget; \
                                 its findings were discarded",
                                meta.id,
                                limit.as_millis()
                            ),
                            None,
                        ));
                        continue;
                    }
                }
                rule_timings.push(RuleTiming {
                    rule_id: meta.id.to_string(),
                    elapsed_micros: elapsed.as_micros(),
                    status: RuleTimingStatus::Completed,
                });
                findings.extend(rule_findings);
            }
            Err(_) => {
                stats.rules_failed += 1;
                rule_timings.push(RuleTiming {
                    rule_id: meta.id.to_string(),
                    elapsed_micros: elapsed.as_micros(),
                    status: RuleTimingStatus::Panicked,
                });
                diagnostics.push(Diagnostic::error(
                    DiagnosticCode::RulePanicked,
                    format!("rule {} panicked; its findings were discarded", meta.id),
                    None,
                ));
            }
        }
    }

    stats.findings_raw = findings.len();
    let mut rejected = 0usize;

    findings.retain_mut(|finding| {
        if let Some(severity) = config.rules.severity_overrides.get(&finding.rule_id) {
            finding.severity = *severity;
        }
        if let Some(confidence) = config.rules.confidence_overrides.get(&finding.rule_id) {
            finding.confidence = *confidence;
        }

        // Relativize and validate the reported location.
        finding.location.file = ctx.relative_path(&finding.location.file);
        if !is_safe_relative(&finding.location.file) {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RuleUnsafeLocation,
                format!(
                    "rule {} produced an unsafe location: {}",
                    finding.rule_id,
                    finding.location.file.display()
                ),
                None,
            ));
            rejected += 1;
            return false;
        }
        let rel = normalize_rel(&finding.location.file);
        if !known.contains(&rel) {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RuleFileOutsideSet,
                format!(
                    "rule {} reported a file outside the analyzed set: {rel}",
                    finding.rule_id
                ),
                None,
            ));
            rejected += 1;
            return false;
        }
        if finding.evidence.trim().is_empty() {
            diagnostics.push(Diagnostic::error(
                DiagnosticCode::RuleMissingEvidence,
                format!(
                    "rule {} produced a finding without evidence",
                    finding.rule_id
                ),
                None,
            ));
            rejected += 1;
            return false;
        }

        finding.refresh_fingerprint();
        finding.severity.meets(config.min_severity) && finding.confidence >= config.min_confidence
    });

    stats.findings_rejected = rejected;

    // Deterministic ordering, then overlap-aware de-duplication.
    findings.sort_by_key(Finding::sort_key);
    deduplicate_overlapping(&mut findings);

    // Apply inline suppression directives. Suppressed findings leave the gate
    // but are always reported with the directive and reason that removed them.
    let suppressions: Vec<Suppression> = loaded
        .sources
        .iter()
        .flat_map(|source| {
            let relative = ctx.relative_path(&source.path);
            source
                .suppressions
                .iter()
                .cloned()
                .map(move |suppression| suppression.with_file(relative.clone()))
        })
        .collect();

    let mut suppressed: Vec<SuppressedFinding> = Vec::new();
    findings.retain(|finding| {
        let file = normalize_rel(&finding.location.file);
        if let Some(suppression) = suppressions
            .iter()
            .find(|s| s.applies_to(&file, finding.location.line, &finding.rule_id))
        {
            suppressed.push(SuppressedFinding {
                finding: finding.clone(),
                suppression: SuppressionInfo {
                    file: suppression.file_label(),
                    line: suppression.line,
                    rules: suppression.targets.label(),
                    reason: suppression.reason.clone(),
                    source: SuppressionSource::Inline,
                    path: None,
                },
            });
            return false;
        }
        true
    });

    // Apply configured suppressions only after inline directives, so an inline
    // directive always takes precedence. Every configured entry is reported,
    // even when its path or rule matches nothing.
    let mut compiled = compile_config_suppressions(config, &mut diagnostics);
    findings.retain(|finding| {
        let file = normalize_rel(&finding.location.file);
        let mut chosen: Option<usize> = None;
        for (index, suppression) in compiled.iter_mut().enumerate() {
            let path_matches = suppression
                .matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(&file));
            if !path_matches {
                continue;
            }
            suppression.report.matched += 1;
            if chosen.is_none() && suppression.rule_matches(&finding.rule_id) {
                chosen = Some(index);
            }
        }
        let Some(index) = chosen else {
            return true;
        };
        let suppression = &mut compiled[index];
        suppression.report.findings_suppressed += 1;
        suppression.report.applied = true;
        suppressed.push(SuppressedFinding {
            finding: finding.clone(),
            suppression: SuppressionInfo {
                file: file.clone(),
                line: finding.location.line,
                rules: suppression.rule.clone(),
                reason: suppression.reason.clone(),
                source: SuppressionSource::Config,
                path: Some(suppression.path.clone()),
            },
        });
        false
    });

    let config_suppressions: Vec<ConfigSuppressionReport> = compiled
        .into_iter()
        .map(|suppression| suppression.report)
        .collect();

    stats.suppressions_detected = suppressions.len();
    stats.findings_suppressed = suppressed.len();
    stats.findings_suppressed_by_config = config_suppressions
        .iter()
        .map(|suppression| suppression.findings_suppressed)
        .sum();
    stats.config_suppressions_detected = config_suppressions.len();
    stats.config_suppressions_matched = config_suppressions
        .iter()
        .filter(|suppression| suppression.matched > 0)
        .count();
    stats.config_suppressions_applied = config_suppressions
        .iter()
        .filter(|suppression| suppression.applied)
        .count();

    // Category counts describe the same findings the gate and severity totals
    // see. A BTreeMap keeps the JSON key order stable across runs.
    stats.findings_by_category = findings
        .iter()
        .fold(BTreeMap::new(), |mut counts, finding| {
            *counts
                .entry(finding.category.as_str().to_string())
                .or_insert(0) += 1;
            counts
        });

    ScanOutcome {
        project: loaded.project.clone(),
        findings,
        diagnostics,
        stats,
        config: config.clone(),
        suppressions,
        suppressed,
        config_suppressions,
        truncation: None,
        rule_timings,
    }
}

/// Loads and scans a directory in one step.
pub fn run_scan(
    root: &Path,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> Result<ScanOutcome, ScanError> {
    let loaded = project::load(root, &config.discovery_options())?;
    Ok(scan(&loaded, registry, config))
}

/// Merges the outcomes of scanning several roots into one deterministic report.
///
/// `labels` holds one prefix per outcome (in the same order); a label of `""`
/// or `"."` leaves that root's paths unprefixed. Prefixing keeps locations from
/// different roots unambiguous. Findings are re-sorted and de-duplicated by
/// fingerprint, per-root statistics are combined, and the merged project
/// reports the strongest classification seen across the roots.
pub fn merge(outcomes: Vec<ScanOutcome>, labels: &[String]) -> ScanOutcome {
    assert_eq!(outcomes.len(), labels.len(), "one label per outcome");

    // The CLI scans every root with the same configuration, so any outcome's
    // effective config is representative. Keep a clone before consuming them.
    let config = outcomes
        .first()
        .map(|outcome| outcome.config.clone())
        .unwrap_or_default();

    let mut findings: Vec<Finding> = Vec::new();
    let mut diagnostics: Vec<Diagnostic> = Vec::new();
    let mut suppressions: Vec<Suppression> = Vec::new();
    let mut suppressed: Vec<SuppressedFinding> = Vec::new();
    let mut config_suppressions: Vec<ConfigSuppressionReport> = Vec::new();
    let mut stats = ScanStats::default();
    let mut projects: Vec<Project> = Vec::new();
    let mut timings: BTreeMap<String, (u128, RuleTimingStatus)> = BTreeMap::new();

    for (mut outcome, label) in outcomes.into_iter().zip(labels.iter()) {
        if let Some(prefix) = prefix_for(label) {
            for finding in &mut outcome.findings {
                prepend_location(finding, &prefix);
            }
            for entry in &mut outcome.suppressed {
                prepend_location(&mut entry.finding, &prefix);
                entry.suppression.file = prefix_path(&entry.suppression.file, &prefix);
            }
            for suppression in &mut outcome.suppressions {
                let file = suppression.file.to_string_lossy().into_owned();
                suppression.file = PathBuf::from(prefix_path(&file, &prefix));
            }
            for diagnostic in &mut outcome.diagnostics {
                if let Some(path) = &diagnostic.path {
                    let file = path.to_string_lossy().into_owned();
                    diagnostic.path = Some(PathBuf::from(prefix_path(&file, &prefix)));
                }
            }
        }

        findings.append(&mut outcome.findings);
        diagnostics.append(&mut outcome.diagnostics);
        suppressions.append(&mut outcome.suppressions);
        suppressed.append(&mut outcome.suppressed);
        config_suppressions.append(&mut outcome.config_suppressions);
        merge_stats(&mut stats, &outcome.stats);
        for timing in &outcome.rule_timings {
            let entry = timings
                .entry(timing.rule_id.clone())
                .or_insert((0, RuleTimingStatus::Completed));
            entry.0 += timing.elapsed_micros;
            entry.1 = merge_timing_status(entry.1, timing.status);
        }
        projects.push(outcome.project);
    }

    let config_suppressions = merge_config_suppression_reports(config_suppressions);
    stats.config_suppressions_detected = config_suppressions.len();
    stats.config_suppressions_matched = config_suppressions
        .iter()
        .filter(|suppression| suppression.matched > 0)
        .count();
    stats.config_suppressions_applied = config_suppressions
        .iter()
        .filter(|suppression| suppression.applied)
        .count();
    stats.findings_suppressed_by_config = config_suppressions
        .iter()
        .map(|suppression| suppression.findings_suppressed)
        .sum();

    let rule_timings: Vec<RuleTiming> = timings
        .into_iter()
        .map(|(rule_id, (elapsed_micros, status))| RuleTiming {
            rule_id,
            elapsed_micros,
            status,
        })
        .collect();

    findings.sort_by_key(|finding| finding.sort_key());
    findings.dedup_by(|a, b| a.fingerprint == b.fingerprint);

    ScanOutcome {
        project: merge_projects(projects),
        findings,
        diagnostics,
        stats,
        config,
        suppressions,
        suppressed,
        config_suppressions,
        truncation: None,
        rule_timings,
    }
}

/// Chooses the most severe status when the same rule ran under several roots.
fn merge_timing_status(a: RuleTimingStatus, b: RuleTimingStatus) -> RuleTimingStatus {
    if a == RuleTimingStatus::Panicked || b == RuleTimingStatus::Panicked {
        RuleTimingStatus::Panicked
    } else if a == RuleTimingStatus::TimedOut || b == RuleTimingStatus::TimedOut {
        RuleTimingStatus::TimedOut
    } else {
        RuleTimingStatus::Completed
    }
}

/// Returns the location prefix for a root label, or `None` when it adds nothing.
fn prefix_for(label: &str) -> Option<String> {
    let trimmed = label.trim_matches('/');
    if trimmed.is_empty() || trimmed == "." {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Joins a relative path with a root prefix, dropping a leading `./`.
fn prefix_path(path: &str, prefix: &str) -> String {
    let path = path.replace('\\', "/");
    let path = path.strip_prefix("./").unwrap_or(&path);
    if path.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{path}")
    }
}

/// Rewrites a finding's location to sit under `prefix` and refreshes its hash.
fn prepend_location(finding: &mut Finding, prefix: &str) {
    let file = finding.location.file.to_string_lossy().into_owned();
    finding.location.file = PathBuf::from(prefix_path(&file, prefix));
    finding.refresh_fingerprint();
}

/// Merges identical configured suppression audit entries across roots.
fn merge_config_suppression_reports(
    mut reports: Vec<ConfigSuppressionReport>,
) -> Vec<ConfigSuppressionReport> {
    reports.sort_by(|a, b| {
        (
            a.path.as_str(),
            a.rule.as_str(),
            a.reason.as_deref().unwrap_or_default(),
        )
            .cmp(&(
                b.path.as_str(),
                b.rule.as_str(),
                b.reason.as_deref().unwrap_or_default(),
            ))
    });
    let mut merged: Vec<ConfigSuppressionReport> = Vec::new();
    for report in reports {
        if let Some(last) = merged.last_mut() {
            if last.path == report.path && last.rule == report.rule && last.reason == report.reason
            {
                last.matched += report.matched;
                last.findings_suppressed += report.findings_suppressed;
                last.applied |= report.applied;
                continue;
            }
        }
        merged.push(report);
    }
    merged
}

/// Combines per-root statistics; rule counts are identical across roots.
fn merge_stats(stats: &mut ScanStats, other: &ScanStats) {
    if stats.rules_run == 0 && stats.rules_skipped == 0 {
        stats.rules_run = other.rules_run;
        stats.rules_skipped = other.rules_skipped;
    }
    stats.files_analyzed += other.files_analyzed;
    stats.files_parsed += other.files_parsed;
    stats.files_failed += other.files_failed;
    stats.files_skipped += other.files_skipped;
    stats.findings_raw += other.findings_raw;
    stats.findings_rejected += other.findings_rejected;
    stats.suppressions_detected += other.suppressions_detected;
    stats.findings_suppressed += other.findings_suppressed;
    stats.findings_suppressed_by_config += other.findings_suppressed_by_config;
    stats.config_suppressions_detected += other.config_suppressions_detected;
    stats.config_suppressions_matched += other.config_suppressions_matched;
    stats.config_suppressions_applied += other.config_suppressions_applied;
    stats.generated_files_marked += other.generated_files_marked;
    stats.generated_files_excluded += other.generated_files_excluded;
    for (category, count) in &other.findings_by_category {
        *stats
            .findings_by_category
            .entry(category.clone())
            .or_insert(0) += count;
    }
}

/// Ranks project classifications so the strongest one can be selected.
fn kind_rank(kind: ProjectKind) -> u8 {
    match kind {
        ProjectKind::GenericRust => 0,
        ProjectKind::LikelySoroban => 1,
        ProjectKind::ConfirmedSoroban => 2,
    }
}

/// Merges per-root project metadata into a single summary anchored at `.`.
fn merge_projects(projects: Vec<Project>) -> Project {
    let mut kind = ProjectKind::GenericRust;
    let mut manifests = Vec::new();
    let mut diagnostics = Vec::new();
    let mut soroban = SorobanInfo::default();
    let mut source_files = 0usize;

    for project in projects {
        if kind_rank(project.kind) > kind_rank(kind) {
            kind = project.kind;
        }
        source_files += project.source_files;
        soroban.has_sdk_dependency |= project.soroban.has_sdk_dependency;
        soroban.contract_macros_found |= project.soroban.contract_macros_found;
        for version in project.soroban.sdk_versions {
            if !soroban.sdk_versions.contains(&version) {
                soroban.sdk_versions.push(version);
            }
        }
        for evidence in project.soroban.evidence {
            if !soroban.evidence.contains(&evidence) {
                soroban.evidence.push(evidence);
            }
        }
        manifests.extend(project.manifests);
        diagnostics.extend(project.diagnostics);
    }

    soroban.sdk_versions.sort();

    Project {
        root: PathBuf::from("."),
        kind,
        manifests,
        soroban,
        source_files,
        diagnostics,
    }
}

/// Builds a synthetic single-file project from an in-memory source string.
///
/// This is useful for embedding and for regression tests. The synthetic project
/// is treated as Soroban when the source contains a Soroban SDK dependency
/// marker (assumed) or a contract definition.
pub fn synthetic_loaded(src: &str, file_name: &str) -> LoadedProject {
    synthetic_loaded_with_options(src, file_name, false)
}

/// Builds a synthetic single-file project, optionally pruning `#[cfg(test)]`
/// items before analysis.
pub fn synthetic_loaded_with_options(
    src: &str,
    file_name: &str,
    exclude_tests: bool,
) -> LoadedProject {
    let root = std::path::PathBuf::from(".");
    let path = std::path::PathBuf::from(file_name);
    let parsed = crate::source::parse_source_with_options(&path, &root, src, exclude_tests);

    let mut diagnostics = Vec::new();
    if let Some(err) = &parsed.parse_error {
        diagnostics.push(Diagnostic::warning(
            DiagnosticCode::ParseFailed,
            format!("failed to parse source: {err}"),
            Some(path.clone()),
        ));
    }
    if parsed.is_generated() {
        diagnostics.push(Diagnostic::info(
            DiagnosticCode::GeneratedFileMarked,
            format!(
                "source file is marked as generated ({} marker(s)); findings are still reported",
                parsed.generated_markers.len()
            ),
            Some(path.clone()),
        ));
    }
    if !parsed.macro_invocations.is_empty() {
        let mut names: Vec<&str> = parsed
            .macro_invocations
            .iter()
            .map(|invocation| invocation.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        let shown = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
        let suffix = if names.len() > 5 {
            format!(" (+{} more)", names.len() - 5)
        } else {
            String::new()
        };
        diagnostics.push(Diagnostic::info(
            DiagnosticCode::UnexpandedMacro,
            format!(
                "{} macro invocation(s) were not expanded: {shown}{suffix}",
                parsed.macro_invocations.len()
            ),
            Some(path.clone()),
        ));
    }

    let mut info = crate::model::SorobanInfo {
        has_sdk_dependency: true,
        ..crate::model::SorobanInfo::default()
    };
    for location in &parsed.contract_definitions {
        crate::soroban::note_contract_definition(&mut info, location);
    }
    let kind = crate::soroban::classify(&info);

    let project = Project {
        root,
        kind,
        manifests: Vec::new(),
        soroban: info,
        source_files: 1,
        diagnostics,
    };
    LoadedProject {
        project,
        sources: vec![parsed],
        generated_files_excluded: 0,
    }
}

/// Builds a synthetic single-file project using the effective scan options.
pub fn synthetic_loaded_with_config(
    src: &str,
    file_name: &str,
    config: &ScanConfig,
) -> LoadedProject {
    let mut loaded = synthetic_loaded_with_options(
        src,
        file_name,
        config.exclude_tests || !config.include_cfg_test,
    );
    if config.exclude_generated && loaded.sources.iter().any(|source| source.is_generated()) {
        let path = std::path::PathBuf::from(file_name);
        loaded.sources.clear();
        loaded.generated_files_excluded = 1;
        loaded
            .project
            .diagnostics
            .retain(|diagnostic| diagnostic.code != DiagnosticCode::GeneratedFileMarked);
        loaded.project.diagnostics.push(Diagnostic::info(
            DiagnosticCode::GeneratedFileExcluded,
            "excluding generated source file (exclude_generated is enabled)".to_string(),
            Some(path),
        ));
    }
    loaded
}

/// Scans an in-memory source string as a synthetic single-file project.
pub fn scan_source_str(
    src: &str,
    file_name: &str,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> ScanOutcome {
    scan(
        &synthetic_loaded_with_config(src, file_name, config),
        registry,
        config,
    )
}

/// Scans an in-memory manifest as a manifest-only project.
///
/// Useful for manifest-level rules such as SS-015 and for tests. No source
/// files are parsed, so source-based rules have nothing to inspect.
pub fn scan_manifest_str(
    file_name: &str,
    content: &str,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> Result<ScanOutcome, ScanError> {
    let manifest = crate::manifest::parse_manifest(Path::new(file_name), content)?;
    let manifests = vec![manifest];
    let soroban = crate::soroban::analyze_manifests(&manifests);
    let project = Project {
        root: PathBuf::from("."),
        kind: crate::soroban::classify(&soroban),
        manifests,
        soroban,
        source_files: 0,
        diagnostics: Vec::new(),
    };
    let loaded = LoadedProject {
        project,
        sources: Vec::new(),
        generated_files_excluded: 0,
    };
    Ok(scan(&loaded, registry, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::confidence::Confidence;
    use crate::finding::SourceLocation;
    use crate::rule::{Rule, RuleMetadata};
    use crate::severity::Severity;
    use std::path::PathBuf;

    fn tmpdir(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "soroban-scan-engine-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn dedup_meta(rule_id: &'static str) -> RuleMetadata {
        RuleMetadata::new(
            rule_id,
            "Test rule",
            "test description",
            Category::Authorization,
            Severity::High,
            Confidence::Medium,
            "fix it",
        )
    }

    fn dedup_finding(
        rule_id: &'static str,
        file: &str,
        line: usize,
        end_line: usize,
        column: usize,
        evidence: &str,
    ) -> Finding {
        let location = SourceLocation::with_column(file, line, column).with_end(end_line, None);
        Finding::new(&dedup_meta(rule_id), location, evidence)
    }

    #[test]
    fn dedup_collapses_overlapping_spans_for_the_same_rule_and_file() {
        let mut findings = vec![
            dedup_finding("SS-001", "src/lib.rs", 5, 9, 5, "first"),
            dedup_finding("SS-001", "src/lib.rs", 7, 12, 9, "second"),
        ];

        deduplicate_overlapping(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.line, 5);
        assert_eq!(findings[0].evidence, "first");
    }

    #[test]
    fn dedup_prefers_the_narrower_span_at_the_same_start() {
        let mut findings = vec![
            dedup_finding("SS-001", "src/lib.rs", 5, 20, 5, "wide"),
            dedup_finding("SS-001", "src/lib.rs", 5, 7, 5, "narrow"),
        ];

        deduplicate_overlapping(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence, "narrow");
    }

    #[test]
    fn dedup_keeps_adjacent_spans() {
        let mut findings = vec![
            dedup_finding("SS-001", "src/lib.rs", 1, 2, 1, "first"),
            dedup_finding("SS-001", "src/lib.rs", 3, 4, 1, "second"),
        ];

        deduplicate_overlapping(&mut findings);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dedup_never_merges_different_rules_or_files() {
        let mut findings = vec![
            dedup_finding("SS-001", "src/lib.rs", 5, 9, 5, "rule one"),
            dedup_finding("SS-002", "src/lib.rs", 5, 9, 5, "rule two"),
            dedup_finding("SS-001", "src/other.rs", 5, 9, 5, "other file"),
        ];

        deduplicate_overlapping(&mut findings);

        assert_eq!(findings.len(), 3);
    }

    #[test]
    fn dedup_keeps_same_line_findings_at_distinct_columns() {
        let mut findings = vec![
            dedup_finding("SS-007", "src/lib.rs", 5, 5, 5, "first address"),
            dedup_finding("SS-007", "src/lib.rs", 5, 5, 20, "second address"),
        ];

        deduplicate_overlapping(&mut findings);

        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn dedup_collapses_same_line_findings_with_overlapping_columns() {
        let mut left = dedup_finding("SS-007", "src/lib.rs", 5, 5, 5, "first");
        left.location.end_column = Some(12);
        let mut right = dedup_finding("SS-007", "src/lib.rs", 5, 5, 8, "second");
        right.location.end_column = Some(15);
        let mut findings = vec![left, right];

        deduplicate_overlapping(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].location.column, Some(5));
    }

    #[test]
    fn dedup_collapses_exact_duplicates() {
        let mut findings = vec![
            dedup_finding("SS-001", "src/lib.rs", 5, 5, 5, "same"),
            dedup_finding("SS-001", "src/lib.rs", 5, 5, 5, "same"),
        ];

        deduplicate_overlapping(&mut findings);

        assert_eq!(findings.len(), 1);
    }

    fn project_fixture(name: &str) -> PathBuf {
        let root = tmpdir(name);
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n[dependencies]\nsoroban-sdk = \"21.0.0\"\n",
        );
        write(&root.join("src/lib.rs"), "fn a() {}\nfn b() {}\n");
        root
    }

    struct OneFindingRule {
        meta: RuleMetadata,
    }

    impl OneFindingRule {
        fn new(severity: Severity) -> Self {
            OneFindingRule {
                meta: RuleMetadata::new(
                    "SS-001",
                    "Test rule",
                    "test description",
                    Category::Authorization,
                    severity,
                    Confidence::Medium,
                    "fix it",
                ),
            }
        }
    }

    impl Rule for OneFindingRule {
        fn metadata(&self) -> &RuleMetadata {
            &self.meta
        }
        fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
            if let Some(source) = ctx.sources().first() {
                let loc = SourceLocation::new(ctx.relative_path(&source.path), 1);
                out.push(Finding::new(&self.meta, loc, "fn a() {}"));
            }
        }
    }

    struct FabricatingRule {
        meta: RuleMetadata,
    }

    impl Rule for FabricatingRule {
        fn metadata(&self) -> &RuleMetadata {
            &self.meta
        }
        fn analyze(&self, _ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
            out.push(Finding::new(
                &self.meta,
                SourceLocation::new("../../etc/passwd", 1),
                "made up",
            ));
        }
    }

    fn fabricator() -> FabricatingRule {
        FabricatingRule {
            meta: RuleMetadata::new(
                "SS-002",
                "Fabricator",
                "bad",
                Category::Unsafe,
                Severity::High,
                Confidence::High,
                "n/a",
            ),
        }
    }

    #[test]
    fn runs_rules_and_emits_findings() {
        let root = project_fixture("run");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();
        let outcome = scan(&loaded, &registry, &ScanConfig::default());
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.stats.rules_run, 1);
        assert_eq!(outcome.findings[0].severity, Severity::High);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn filters_below_min_severity() {
        let root = project_fixture("filter");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::Low)))
            .unwrap();
        let config = ScanConfig {
            min_severity: Severity::Medium,
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);
        assert!(outcome.findings.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_fabricated_locations() {
        let root = project_fixture("fabricate");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry.register(Box::new(fabricator())).unwrap();
        let outcome = scan(&loaded, &registry, &ScanConfig::default());
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.stats.findings_rejected, 1);
        assert!(outcome
            .diagnostics
            .iter()
            .any(|d| d.message.contains("unsafe location")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let root = project_fixture("disabled");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();
        let config = ScanConfig {
            rules: crate::config::RulesConfig {
                disabled: vec!["SS-001".into()],
                ..crate::config::RulesConfig::default()
            },
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.stats.rules_skipped, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn disabled_categories_are_skipped() {
        let root = project_fixture("disabled-category");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();
        let config = ScanConfig {
            rules: crate::config::RulesConfig {
                disabled_categories: vec![Category::Authorization],
                ..crate::config::RulesConfig::default()
            },
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);
        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.stats.rules_skipped, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn enabled_categories_limit_rule_selection() {
        let root = project_fixture("enabled-category");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();

        // The rule is in `authorization`, so a different category excludes it.
        let other = ScanConfig {
            rules: crate::config::RulesConfig {
                enabled_categories: vec![Category::Storage],
                ..crate::config::RulesConfig::default()
            },
            ..ScanConfig::default()
        };
        let skipped = scan(&loaded, &registry, &other);
        assert!(skipped.findings.is_empty());
        assert_eq!(skipped.stats.rules_skipped, 1);

        // Selecting the matching category runs it.
        let matching = ScanConfig {
            rules: crate::config::RulesConfig {
                enabled_categories: vec![Category::Authorization],
                ..crate::config::RulesConfig::default()
            },
            ..ScanConfig::default()
        };
        let ran = scan(&loaded, &registry, &matching);
        assert_eq!(ran.findings.len(), 1);
        assert_eq!(ran.stats.rules_run, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn category_filters_apply_before_severity_overrides() {
        let root = project_fixture("category-overrides");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::Low)))
            .unwrap();
        let config = ScanConfig {
            rules: crate::config::RulesConfig {
                disabled_categories: vec![Category::Authorization],
                severity_overrides: [("SS-001".to_string(), Severity::Critical)]
                    .into_iter()
                    .collect(),
                ..crate::config::RulesConfig::default()
            },
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);
        assert!(
            outcome.findings.is_empty(),
            "a category-disabled rule must not be rescued by a severity override"
        );
        assert_eq!(outcome.stats.rules_skipped, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inactive_overrides_emit_config_diagnostics() {
        let root = project_fixture("override-diagnostics");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();

        let config = ScanConfig {
            rules: crate::config::RulesConfig {
                disabled: vec!["SS-001".into()],
                severity_overrides: [("SS-001".to_string(), Severity::Critical)]
                    .into_iter()
                    .collect(),
                confidence_overrides: [("SS-999".to_string(), Confidence::High)]
                    .into_iter()
                    .collect(),
                ..crate::config::RulesConfig::default()
            },
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);

        assert!(outcome.findings.is_empty());
        let messages: Vec<&str> = outcome
            .diagnostics
            .iter()
            .filter(|d| d.code == crate::model::DiagnosticCode::IneffectiveOverride)
            .map(|d| d.message.as_str())
            .collect();
        assert_eq!(messages.len(), 2, "got: {messages:?}");
        assert!(
            messages.iter().any(|message| message.contains("SS-001")
                && message.contains("disabled by configuration")),
            "got: {messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("SS-999") && message.contains("unknown rule id")),
            "got: {messages:?}"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn stats_include_parse_telemetry() {
        let root = tmpdir("parse-telemetry");
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n",
        );
        write(&root.join("src/lib.rs"), "fn good() {}\n");
        write(&root.join("src/broken.rs"), "fn broken( {\n");

        let mut loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        // Simulate one discovered file that discovery skipped before parsing.
        loaded.project.source_files = 3;

        let outcome = scan(&loaded, &RuleRegistry::new(), &ScanConfig::default());
        assert_eq!(outcome.stats.files_analyzed, 2);
        assert_eq!(outcome.stats.files_parsed, 1);
        assert_eq!(outcome.stats.files_failed, 1);
        assert_eq!(outcome.stats.files_skipped, 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn scanning_is_deterministic() {
        let root = project_fixture("determinism");
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();
        let a = scan(&loaded, &registry, &ScanConfig::default());
        let b = scan(&loaded, &registry, &ScanConfig::default());
        assert_eq!(
            serde_json::to_string(&a.findings).unwrap(),
            serde_json::to_string(&b.findings).unwrap()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    struct LocatedRule {
        meta: RuleMetadata,
        line: usize,
    }

    impl LocatedRule {
        fn new(severity: Severity, line: usize) -> Self {
            LocatedRule {
                meta: RuleMetadata::new(
                    "SS-001",
                    "Located rule",
                    "reports at a fixed line",
                    Category::Authorization,
                    severity,
                    Confidence::Medium,
                    "fix it",
                ),
                line,
            }
        }
    }

    impl Rule for LocatedRule {
        fn metadata(&self) -> &RuleMetadata {
            &self.meta
        }
        fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
            if let Some(source) = ctx.sources().first() {
                let loc = SourceLocation::new(ctx.relative_path(&source.path), self.line);
                out.push(Finding::new(&self.meta, loc, "located evidence"));
            }
        }
    }

    fn project_with_source(name: &str, src: &str) -> (PathBuf, LoadedProject) {
        let root = tmpdir(name);
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n[dependencies]\nsoroban-sdk = \"21.0.0\"\n",
        );
        write(&root.join("src/lib.rs"), src);
        let loaded = project::load(&root, &ScanConfig::default().discovery_options()).unwrap();
        (root, loaded)
    }

    fn located_registry(severity: Severity, line: usize) -> RuleRegistry {
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(LocatedRule::new(severity, line)))
            .unwrap();
        registry
    }

    #[test]
    fn inline_suppression_excludes_the_finding_but_reports_it() {
        let (root, loaded) = project_with_source(
            "suppress",
            "// soroban-scan: ignore SS-001 -- reviewed by security team\nfn a() {}\n",
        );
        let registry = located_registry(Severity::High, 2);
        let outcome = scan(&loaded, &registry, &ScanConfig::default());

        assert!(
            outcome.findings.is_empty(),
            "suppressed finding must not reach the gate"
        );
        assert_eq!(outcome.stats.findings_suppressed, 1);
        assert_eq!(outcome.stats.suppressions_detected, 1);
        assert_eq!(outcome.suppressed.len(), 1);
        let suppressed = &outcome.suppressed[0];
        assert_eq!(suppressed.finding.rule_id, "SS-001");
        assert_eq!(suppressed.finding.location.line, 2);
        assert_eq!(suppressed.suppression.line, 1);
        assert_eq!(suppressed.suppression.rules, "SS-001");
        assert_eq!(suppressed.suppression.file, "src/lib.rs");
        assert_eq!(
            suppressed.suppression.reason.as_deref(),
            Some("reviewed by security team")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inline_suppression_for_another_rule_keeps_the_finding() {
        let (root, loaded) = project_with_source(
            "suppress-other",
            "// soroban-scan: ignore SS-002\nfn a() {}\n",
        );
        let registry = located_registry(Severity::High, 2);
        let outcome = scan(&loaded, &registry, &ScanConfig::default());

        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.suppressed.is_empty());
        assert_eq!(outcome.stats.findings_suppressed, 0);
        assert_eq!(outcome.stats.suppressions_detected, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inline_suppression_with_all_targets_is_reported_in_full() {
        let (root, loaded) = project_with_source(
            "suppress-all",
            "// soroban-scan: ignore all -- generated code\nfn a() {}\n",
        );
        let registry = located_registry(Severity::High, 2);
        let outcome = scan(&loaded, &registry, &ScanConfig::default());

        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.suppressed.len(), 1);
        assert_eq!(outcome.suppressed[0].suppression.rules, "all");
        assert_eq!(
            outcome.suppressed[0].suppression.reason.as_deref(),
            Some("generated code")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    struct SleepingRule {
        meta: RuleMetadata,
    }

    impl SleepingRule {
        fn new() -> Self {
            SleepingRule {
                meta: RuleMetadata::new(
                    "SS-901",
                    "Sleeping rule",
                    "slow test rule",
                    Category::Authorization,
                    Severity::Low,
                    Confidence::Low,
                    "n/a",
                ),
            }
        }
    }

    impl Rule for SleepingRule {
        fn metadata(&self) -> &RuleMetadata {
            &self.meta
        }
        fn analyze(&self, _ctx: &AnalysisContext<'_>, _out: &mut Vec<Finding>) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    struct PanickingRule {
        meta: RuleMetadata,
    }

    impl PanickingRule {
        fn new() -> Self {
            Self::with_id("SS-902")
        }

        fn with_id(id: &'static str) -> Self {
            PanickingRule {
                meta: RuleMetadata::new(
                    id,
                    "Panicking rule",
                    "panicking test rule",
                    Category::Authorization,
                    Severity::Low,
                    Confidence::Low,
                    "n/a",
                ),
            }
        }
    }

    impl Rule for PanickingRule {
        fn metadata(&self) -> &RuleMetadata {
            &self.meta
        }
        fn analyze(&self, _ctx: &AnalysisContext<'_>, _out: &mut Vec<Finding>) {
            panic!("intentional test panic");
        }
    }

    #[test]
    fn slow_rule_findings_are_discarded_at_the_execution_budget() {
        let (root, loaded) = project_with_source("slow-rule", "fn a() {}\n");
        let mut registry = RuleRegistry::new();
        registry.register(Box::new(SleepingRule::new())).unwrap();
        let config = ScanConfig {
            rules: crate::config::RulesConfig {
                rule_time_budget_ms: Some(10),
                ..crate::config::RulesConfig::default()
            },
            ..ScanConfig::default()
        };

        let outcome = scan(&loaded, &registry, &config);

        assert_eq!(outcome.stats.rules_run, 1);
        assert_eq!(outcome.stats.rules_timed_out, 1);
        assert!(outcome.findings.is_empty());
        assert!(outcome
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::RuleTimeBudgetExceeded));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn panicking_rules_are_isolated_and_reported() {
        let (root, loaded) = project_with_source("panic-rule", "fn a() {}\n");
        let mut registry = RuleRegistry::new();
        registry.register(Box::new(PanickingRule::new())).unwrap();

        let outcome = scan(&loaded, &registry, &ScanConfig::default());

        assert_eq!(outcome.stats.rules_run, 1);
        assert_eq!(outcome.stats.rules_failed, 1);
        assert_eq!(outcome.stats.rules_timed_out, 0);
        assert!(outcome.findings.is_empty());
        assert!(outcome
            .diagnostics
            .iter()
            .any(|d| d.code == DiagnosticCode::RulePanicked));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_panicking_rule_does_not_stop_other_rules() {
        let (root, loaded) = project_with_source("panic-isolation", "fn a() {}\n");
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();
        registry.register(Box::new(PanickingRule::new())).unwrap();

        let outcome = scan(&loaded, &registry, &ScanConfig::default());

        assert_eq!(outcome.stats.rules_failed, 1);
        assert_eq!(outcome.stats.rules_run, 2);
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].rule_id, "SS-001");
        assert!(outcome
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::RulePanicked));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rule_execution_order_is_independent_of_registration_order() {
        let (root, loaded) = project_with_source("rule-order", "fn a() {}\n");

        let mut forward = RuleRegistry::new();
        forward
            .register(Box::new(PanickingRule::with_id("SS-902")))
            .unwrap();
        forward
            .register(Box::new(PanickingRule::with_id("SS-903")))
            .unwrap();

        let mut reversed = RuleRegistry::new();
        reversed
            .register(Box::new(PanickingRule::with_id("SS-903")))
            .unwrap();
        reversed
            .register(Box::new(PanickingRule::with_id("SS-902")))
            .unwrap();

        let forward_outcome = scan(&loaded, &forward, &ScanConfig::default());
        let reversed_outcome = scan(&loaded, &reversed, &ScanConfig::default());

        let forward_timings: Vec<_> = forward_outcome
            .rule_timings
            .iter()
            .map(|timing| (timing.rule_id.as_str(), timing.status))
            .collect();
        let reversed_timings: Vec<_> = reversed_outcome
            .rule_timings
            .iter()
            .map(|timing| (timing.rule_id.as_str(), timing.status))
            .collect();
        assert_eq!(forward_timings, reversed_timings);
        assert_eq!(
            forward_timings,
            vec![
                ("SS-902", RuleTimingStatus::Panicked),
                ("SS-903", RuleTimingStatus::Panicked)
            ]
        );
        assert_eq!(forward_outcome.diagnostics, reversed_outcome.diagnostics);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rule_timings_record_completed_and_panicked_rules() {
        let (root, loaded) = project_with_source("timings", "fn a() {}\n");
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();
        registry.register(Box::new(PanickingRule::new())).unwrap();

        let outcome = scan(&loaded, &registry, &ScanConfig::default());

        let ids: Vec<_> = outcome
            .rule_timings
            .iter()
            .map(|timing| (timing.rule_id.as_str(), timing.status))
            .collect();
        assert_eq!(
            ids,
            vec![
                ("SS-001", RuleTimingStatus::Completed),
                ("SS-902", RuleTimingStatus::Panicked)
            ]
        );
        assert_eq!(outcome.rule_timings.len(), 2);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn merged_outcomes_sum_timings_per_rule() {
        let (root_a, loaded_a) = project_with_source("timings-a", "fn a() {}\n");
        let (root_b, loaded_b) = project_with_source("timings-b", "fn b() {}\n");
        let mut registry = RuleRegistry::new();
        registry
            .register(Box::new(OneFindingRule::new(Severity::High)))
            .unwrap();

        let first = scan(&loaded_a, &registry, &ScanConfig::default());
        let second = scan(&loaded_b, &registry, &ScanConfig::default());
        let merged = merge(
            vec![first.clone(), second.clone()],
            &["a".to_string(), "b".to_string()],
        );

        assert_eq!(merged.rule_timings.len(), 1);
        let expected = first.rule_timings[0].elapsed_micros + second.rule_timings[0].elapsed_micros;
        assert_eq!(merged.rule_timings[0].elapsed_micros, expected);
        assert_eq!(merged.rule_timings[0].status, RuleTimingStatus::Completed);
        let _ = std::fs::remove_dir_all(&root_a);
        let _ = std::fs::remove_dir_all(&root_b);
    }

    #[test]
    fn directives_inside_string_literals_never_suppress() {
        let (root, loaded) = project_with_source(
            "suppress-string",
            "fn a() {\n    let s = \"// soroban-scan: ignore SS-001\";\n}\n",
        );
        let registry = located_registry(Severity::High, 2);
        let outcome = scan(&loaded, &registry, &ScanConfig::default());

        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.suppressed.is_empty());
        assert_eq!(outcome.stats.suppressions_detected, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    fn config_suppression(path: &str, rule: &str) -> crate::config::SuppressionRule {
        crate::config::SuppressionRule {
            path: path.to_string(),
            rule: rule.to_string(),
            reason: Some("accepted for this path".to_string()),
        }
    }

    #[test]
    fn config_suppression_excludes_the_finding_but_reports_it() {
        let (root, loaded) = project_with_source("config-suppress", "fn a() {}\n");
        let registry = located_registry(Severity::High, 1);
        let config = ScanConfig {
            suppressions: vec![config_suppression("src/**", "SS-001")],
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);

        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.stats.findings_suppressed, 1);
        assert_eq!(outcome.stats.findings_suppressed_by_config, 1);
        assert_eq!(outcome.stats.config_suppressions_detected, 1);
        assert_eq!(outcome.stats.config_suppressions_matched, 1);
        assert_eq!(outcome.stats.config_suppressions_applied, 1);
        assert_eq!(outcome.suppressed.len(), 1);
        let suppressed = &outcome.suppressed[0];
        assert_eq!(suppressed.suppression.source, SuppressionSource::Config);
        assert_eq!(suppressed.suppression.path.as_deref(), Some("src/**"));
        assert_eq!(suppressed.suppression.rules, "SS-001");
        assert_eq!(
            suppressed.suppression.reason.as_deref(),
            Some("accepted for this path")
        );
        assert_eq!(outcome.config_suppressions.len(), 1);
        assert!(outcome.config_suppressions[0].applied);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn inline_suppressions_take_precedence_over_configuration() {
        let (root, loaded) = project_with_source(
            "inline-before-config",
            "// soroban-scan: ignore SS-001 -- reviewed inline\nfn a() {}\n",
        );
        let registry = located_registry(Severity::High, 2);
        let config = ScanConfig {
            suppressions: vec![config_suppression("src/**", "all")],
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);

        assert!(outcome.findings.is_empty());
        assert_eq!(outcome.suppressed.len(), 1);
        assert_eq!(
            outcome.suppressed[0].suppression.source,
            SuppressionSource::Inline
        );
        assert_eq!(outcome.config_suppressions[0].matched, 0);
        assert!(!outcome.config_suppressions[0].applied);
        assert_eq!(outcome.stats.config_suppressions_matched, 0);
        assert_eq!(outcome.stats.config_suppressions_applied, 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn config_suppression_that_matches_nothing_is_reported() {
        let (root, loaded) = project_with_source("config-unused", "fn a() {}\n");
        let registry = located_registry(Severity::High, 1);
        let config = ScanConfig {
            suppressions: vec![config_suppression("vendor/**", "all")],
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);

        assert_eq!(outcome.findings.len(), 1);
        assert!(outcome.suppressed.is_empty());
        assert_eq!(outcome.stats.config_suppressions_detected, 1);
        assert_eq!(outcome.stats.config_suppressions_matched, 0);
        assert_eq!(outcome.stats.config_suppressions_applied, 0);
        assert_eq!(outcome.config_suppressions.len(), 1);
        assert_eq!(outcome.config_suppressions[0].matched, 0);
        assert!(!outcome.config_suppressions[0].applied);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn config_suppression_path_match_with_other_rule_keeps_the_finding() {
        let (root, loaded) = project_with_source("config-other-rule", "fn a() {}\n");
        let registry = located_registry(Severity::High, 1);
        let config = ScanConfig {
            suppressions: vec![config_suppression("src/**", "SS-002")],
            ..ScanConfig::default()
        };
        let outcome = scan(&loaded, &registry, &config);

        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.config_suppressions[0].matched, 1);
        assert_eq!(outcome.config_suppressions[0].findings_suppressed, 0);
        assert!(!outcome.config_suppressions[0].applied);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn generated_files_are_marked_by_default_and_excluded_on_request() {
        let src = "// @generated by a tool\nfn a() {}\n";
        let registry = located_registry(Severity::High, 2);

        let marked = scan_source_str(src, "src/lib.rs", &ScanConfig::default(), &registry);
        assert_eq!(marked.stats.generated_files_marked, 1);
        assert_eq!(marked.stats.generated_files_excluded, 0);
        assert_eq!(marked.findings.len(), 1);
        assert!(marked
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::GeneratedFileMarked));

        let excluded = ScanConfig {
            exclude_generated: true,
            ..ScanConfig::default()
        };
        let excluded = scan_source_str(src, "src/lib.rs", &excluded, &registry);
        assert_eq!(excluded.stats.generated_files_marked, 0);
        assert_eq!(excluded.stats.generated_files_excluded, 1);
        assert!(excluded.findings.is_empty());
        assert!(excluded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::GeneratedFileExcluded));
    }
}

#[cfg(test)]
mod path_normalization_tests {
    use super::{is_safe_relative, normalize_rel};
    use std::path::Path;

    #[test]
    fn normalize_rel_emits_forward_slashes_for_native_and_forward_separators() {
        assert_eq!(normalize_rel(Path::new("src/lib.rs")), "src/lib.rs");
        assert_eq!(normalize_rel(Path::new("src\\lib.rs")), "src/lib.rs");
        assert_eq!(
            normalize_rel(Path::new("crates\\core\\src\\lib.rs")),
            "crates/core/src/lib.rs"
        );
    }

    #[test]
    fn normalize_rel_strips_a_leading_current_dir() {
        assert_eq!(normalize_rel(Path::new("./src/lib.rs")), "src/lib.rs");
        // A bare "." is left as-is rather than becoming empty.
        assert_eq!(normalize_rel(Path::new(".")), ".");
    }

    #[test]
    fn normalize_rel_preserves_drive_letters_and_case() {
        assert_eq!(
            normalize_rel(Path::new("C:\\Repo\\Src\\Lib.rs")),
            "C:/Repo/Src/Lib.rs"
        );
        assert_eq!(
            normalize_rel(Path::new("c:/repo/src/lib.rs")),
            "c:/repo/src/lib.rs"
        );
        assert_eq!(
            normalize_rel(Path::new("C:/Repo/Src/Lib.rs")),
            "C:/Repo/Src/Lib.rs"
        );
    }

    #[test]
    fn rel_logic_accepts_both_separator_styles() {
        // Both spellings denote a safe, relative path on every platform.
        assert!(is_safe_relative(Path::new("src/lib.rs")));
        assert!(is_safe_relative(Path::new("src\\lib.rs")));
        assert!(is_safe_relative(Path::new("./src/lib.rs")));
    }

    #[test]
    fn traversal_and_absolute_paths_are_rejected() {
        assert!(!is_safe_relative(Path::new("../secret.rs")));
        assert!(!is_safe_relative(Path::new("src/../../secret.rs")));
        assert!(!is_safe_relative(Path::new("/etc/passwd")));
        assert!(!is_safe_relative(Path::new("")));
    }
}
