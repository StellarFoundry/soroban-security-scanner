//! The scanner pipeline.
//!
//! The engine runs enabled rules over an immutable [`AnalysisContext`],
//! validates every finding against the scan root and known source files,
//! applies configuration overrides and filters, de-duplicates, and sorts the
//! result deterministically.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::ScanConfig;
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
    /// Number of source files analyzed.
    pub files_analyzed: usize,
    /// Findings produced before validation/filtering.
    pub findings_raw: usize,
    /// Findings dropped because they referenced an unknown file.
    pub findings_rejected: usize,
    /// Inline suppression directives detected in the analyzed sources.
    pub suppressions_detected: usize,
    /// Findings excluded from the gate by an inline suppression directive.
    pub findings_suppressed: usize,
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
    /// Findings excluded from the gate by an inline suppression directive.
    pub suppressed: Vec<SuppressedFinding>,
    /// Set when the caller bounded the number of reported findings.
    ///
    /// `None` means the report contains every finding. The gate is always
    /// evaluated before truncation, so this field never changes the exit code.
    pub truncation: Option<FindingTruncation>,
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

/// The directive that suppressed a finding, as reported for auditability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuppressionInfo {
    /// Root-relative, forward-slash path of the file containing the directive.
    pub file: String,
    /// 1-based line of the directive comment.
    pub line: usize,
    /// Rule targets of the directive (for example `SS-001,SS-002`, or `all`).
    pub rules: String,
    /// Reason supplied by the directive, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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

/// Runs the scanner over a loaded project.
pub fn scan(loaded: &LoadedProject, registry: &RuleRegistry, config: &ScanConfig) -> ScanOutcome {
    let ctx = AnalysisContext::new(&loaded.project, &loaded.sources);
    let known: BTreeSet<String> = loaded
        .sources
        .iter()
        .map(|s| normalize_rel(&ctx.relative_path(&s.path)))
        .collect();

    let mut diagnostics = loaded.project.diagnostics.clone();
    let mut findings: Vec<Finding> = Vec::new();
    let mut stats = ScanStats {
        files_analyzed: loaded.sources.len(),
        ..ScanStats::default()
    };

    for rule in registry.rules() {
        let meta = rule.metadata();
        if !rule.enabled_by_default() || !config.rules.is_rule_enabled(meta.id, meta.category) {
            stats.rules_skipped += 1;
            continue;
        }
        stats.rules_run += 1;
        rule.analyze(&ctx, &mut findings);
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

    // Deterministic ordering, then exact de-duplication.
    findings.sort_by_key(Finding::sort_key);
    let mut seen = BTreeSet::new();
    findings.retain(|f| seen.insert(f.identity()));

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
                },
            });
            return false;
        }
        true
    });

    stats.suppressions_detected = suppressions.len();
    stats.findings_suppressed = suppressed.len();

    ScanOutcome {
        project: loaded.project.clone(),
        findings,
        diagnostics,
        stats,
        config: config.clone(),
        suppressions,
        suppressed,
        truncation: None,
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
    let mut stats = ScanStats::default();
    let mut projects: Vec<Project> = Vec::new();

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
        merge_stats(&mut stats, &outcome.stats);
        projects.push(outcome.project);
    }

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
        truncation: None,
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

/// Combines per-root statistics; rule counts are identical across roots.
fn merge_stats(stats: &mut ScanStats, other: &ScanStats) {
    if stats.rules_run == 0 && stats.rules_skipped == 0 {
        stats.rules_run = other.rules_run;
        stats.rules_skipped = other.rules_skipped;
    }
    stats.files_analyzed += other.files_analyzed;
    stats.findings_raw += other.findings_raw;
    stats.findings_rejected += other.findings_rejected;
    stats.suppressions_detected += other.suppressions_detected;
    stats.findings_suppressed += other.findings_suppressed;
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
    }
}

/// Scans an in-memory source string as a synthetic single-file project.
pub fn scan_source_str(
    src: &str,
    file_name: &str,
    config: &ScanConfig,
    registry: &RuleRegistry,
) -> ScanOutcome {
    scan(
        &synthetic_loaded_with_options(src, file_name, config.exclude_tests),
        registry,
        config,
    )
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
}
