//! Reporting: terminal, JSON, SARIF, and Markdown renderers.
//!
//! Machine-readable formats are stable and versioned by the tool version. No
//! renderer ever emits environment variables, absolute user paths, or secrets.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::baseline::{BaselineReport, BaselineStatus};
use crate::config::ScanConfig;
use crate::engine::{
    ConfigSuppressionReport, FindingTruncation, ScanOutcome, SuppressedFinding, SuppressionInfo,
    SuppressionSource,
};
use crate::finding::Finding;
use crate::model::Diagnostic;
use crate::registry::RuleRegistry;
use crate::rule::RuleMetadata;
use crate::severity::Severity;

/// Tool name used in reports.
pub const TOOL_NAME: &str = "soroban-scan";
/// Tool homepage used in reports.
pub const TOOL_URL: &str = "https://github.com/AyinkxLab/soroban-security-scanner";
/// SARIF schema URI.
pub const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
/// Version of the machine-readable scan report contract.
///
/// This is the stable interface between the scanner and downstream consumers
/// (for example the Stellar Contract Observatory). It is independent of the
/// tool version and only changes when the report shape changes in a way
/// consumers must handle. Additive, backward-compatible changes keep the same
/// major value and are documented in `docs/integration/observatory.md`.
pub const REPORT_SCHEMA_VERSION: &str = "1";

/// Output format for scan results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable terminal text.
    Terminal,
    /// Stable JSON.
    Json,
    /// SARIF 2.1.0 for code scanning.
    Sarif,
    /// Markdown report.
    Markdown,
    /// Self-contained HTML report.
    Html,
    /// GitHub Actions workflow annotations (`::error`, `::warning`, `::notice`).
    Github,
    /// JUnit XML for CI test reporters.
    Junit,
}

impl OutputFormat {
    /// Parses a format name.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "terminal" | "text" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "html" => Ok(OutputFormat::Html),
            "github" => Ok(OutputFormat::Github),
            "junit" | "junit-xml" => Ok(OutputFormat::Junit),
            other => Err(format!("unknown output format: {other}")),
        }
    }

    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            OutputFormat::Terminal => "terminal",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Markdown => "markdown",
            OutputFormat::Html => "html",
            OutputFormat::Github => "github",
            OutputFormat::Junit => "junit",
        }
    }
}

/// Renders a scan outcome in the requested format.
pub fn render(outcome: &ScanOutcome, registry: &RuleRegistry, format: OutputFormat) -> String {
    render_with_baseline(outcome, registry, format, None)
}

/// Renders a scan outcome in the requested format, attaching an optional
/// baseline comparison to machine-readable output.
pub fn render_with_baseline(
    outcome: &ScanOutcome,
    registry: &RuleRegistry,
    format: OutputFormat,
    baseline: Option<&BaselineReport>,
) -> String {
    match format {
        OutputFormat::Terminal => render_terminal(outcome),
        OutputFormat::Json => render_json_with_baseline(outcome, baseline)
            .unwrap_or_else(|e| format!("{{\"error\":\"failed to serialize report: {e}\"}}")),
        OutputFormat::Sarif => render_sarif_with_baseline(outcome, registry, baseline),
        OutputFormat::Markdown => render_markdown(outcome),
        OutputFormat::Html => render_html(outcome),
        OutputFormat::Github => render_github(outcome),
        OutputFormat::Junit => render_junit(outcome),
    }
}

/// Escapes text for XML element content and attributes.
fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Renders findings as JUnit XML: one test case per finding, failures only for
/// high and critical severities.
pub fn render_junit(outcome: &ScanOutcome) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let failures = outcome
        .findings
        .iter()
        .filter(|f| matches!(f.severity.as_str(), "high" | "critical"))
        .count();
    out.push_str(&format!(
        "<testsuites name=\"{TOOL_NAME}\"><testsuite name=\"soroban-scan\" tests=\"{}\" failures=\"{failures}\">\n",
        outcome.findings.len()
    ));
    for finding in &outcome.findings {
        let location = format!(
            "{}:{}:{}",
            finding.location.file.display(),
            finding.location.line,
            finding.location.column.unwrap_or(1)
        );
        let name = escape_xml(&format!("{} {location}", finding.rule_id));
        let classname = escape_xml(&format!("soroban-scan.{}", finding.rule_id));
        out.push_str(&format!(
            "<testcase classname=\"{classname}\" name=\"{name}\">"
        ));
        if matches!(finding.severity.as_str(), "high" | "critical") {
            let message = escape_xml(&format!(
                "{}: {} ({})",
                finding.severity.as_str(),
                finding.title,
                finding.evidence
            ));
            out.push_str(&format!(
                "<failure message=\"{message}\">{message}</failure>"
            ));
        }
        out.push_str("</testcase>\n");
    }
    out.push_str("</testsuite></testsuites>\n");
    out
}

/// Renders a suppression file label with the platform path separator, so
/// terminal and Markdown output match the way finding locations are displayed.
fn display_suppression_file(file: &str) -> String {
    file.replace('/', std::path::MAIN_SEPARATOR_STR)
}

fn severity_counts(findings: &[Finding]) -> [usize; 5] {
    let mut counts = [0usize; 5];
    for finding in findings {
        counts[finding.severity.rank() as usize] += 1;
    }
    counts
}

/// Counts findings per rule, sorted by descending count and then rule id.
fn rule_counts(findings: &[Finding]) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.rule_id.as_str()).or_insert(0) += 1;
    }
    let mut rows: Vec<(String, usize)> = counts
        .into_iter()
        .map(|(id, count)| (id.to_string(), count))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    rows
}

/// Counts findings per category, sorted by descending count and then name.
fn category_counts(findings: &[Finding]) -> Vec<(&'static str, usize)> {
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.category.as_str()).or_insert(0) += 1;
    }
    let mut rows: Vec<(&'static str, usize)> = counts.into_iter().collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    rows
}

/// Renders a concise human-readable summary line.
pub fn summary_line(findings: &[Finding]) -> String {
    let counts = severity_counts(findings);
    format!(
        "{} finding(s) — critical: {}, high: {}, medium: {}, low: {}, info: {}",
        findings.len(),
        counts[4],
        counts[3],
        counts[2],
        counts[1],
        counts[0]
    )
}

/// ANSI color policy for human-readable terminal output.
///
/// Color is opt-in and never applied to JSON, SARIF, Markdown, or GitHub
/// annotations. Keeping this as a value (rather than reading the environment
/// during rendering) makes the decision testable and keeps machine output
/// deterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalColor {
    enabled: bool,
}

impl TerminalColor {
    /// Creates a color policy.
    pub fn new(enabled: bool) -> Self {
        TerminalColor { enabled }
    }

    /// Plain, unstyled text.
    pub const PLAIN: Self = TerminalColor { enabled: false };

    /// Whether ANSI escapes are emitted.
    pub fn is_enabled(self) -> bool {
        self.enabled
    }

    fn paint(self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\u{1b}[{code}m{text}\u{1b}[0m")
        } else {
            text.to_string()
        }
    }

    fn severity(self, severity: Severity, padded: &str) -> String {
        let code = match severity {
            Severity::Critical => "1;31",
            Severity::High => "31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "2",
        };
        self.paint(code, padded)
    }
}

/// Renders the terminal report without color.
pub fn render_terminal(outcome: &ScanOutcome) -> String {
    render_terminal_with_color(outcome, TerminalColor::PLAIN)
}

/// Renders the terminal report, optionally with ANSI colors.
pub fn render_terminal_with_color(outcome: &ScanOutcome, color: TerminalColor) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n",
        color.paint("1", &format!("{TOOL_NAME} {}", crate::VERSION))
    ));
    out.push_str(&format!(
        "Project: {} ({})\n",
        outcome.project.root.display(),
        outcome.project.kind
    ));
    out.push_str(&format!(
        "Files: {}  Rules run: {}  Skipped: {}  Suppressions: {}\n",
        outcome.stats.files_analyzed,
        outcome.stats.rules_run,
        outcome.stats.rules_skipped,
        outcome.stats.suppressions_detected
    ));
    out.push_str(&format!(
        "Generated: {} marked, {} excluded  Config suppressions: {} detected, {} applied\n\n",
        outcome.stats.generated_files_marked,
        outcome.stats.generated_files_excluded,
        outcome.stats.config_suppressions_detected,
        outcome.stats.config_suppressions_applied
    ));

    if outcome.findings.is_empty() {
        if outcome.truncation.is_none() {
            out.push_str("No security findings.\n");
        }
    } else {
        let mut current_file: Option<&std::path::Path> = None;
        for finding in &outcome.findings {
            if current_file != Some(finding.location.file.as_path()) {
                current_file = Some(finding.location.file.as_path());
                out.push_str(&format!("\n{}\n", finding.location.file.display()));
            }
            let label = format!("{:<8}", finding.severity.as_str().to_ascii_uppercase());
            out.push_str(&format!(
                "{} {:<7} {}\n",
                color.severity(finding.severity, &label),
                finding.rule_id,
                finding.location.display_label()
            ));
            out.push_str(&format!("         {}\n", finding.title));
            out.push_str(&format!("         confidence: {}\n", finding.confidence));
            let frame = finding
                .evidence
                .lines()
                .next()
                .unwrap_or_default()
                .chars()
                .take(120)
                .collect::<String>();
            out.push_str(&format!("         evidence: {frame}\n"));
            out.push_str(&format!("         fix: {}\n\n", finding.remediation));
        }
        out.push_str(&summary_line(&outcome.findings));
        out.push('\n');
    }
    append_truncation_notice(outcome, &mut out);
    if !outcome.suppressed.is_empty() {
        out.push_str(&format!(
            "\n{} suppressed finding(s):\n",
            outcome.suppressed.len()
        ));
        for suppressed in &outcome.suppressed {
            let label = format!(
                "{:<8}",
                suppressed.finding.severity.as_str().to_ascii_uppercase()
            );
            out.push_str(&format!(
                "  {} {:<7} {}\n",
                color.severity(suppressed.finding.severity, &label),
                suppressed.finding.rule_id,
                suppressed.finding.location.display_label()
            ));
            match suppressed.suppression.source {
                SuppressionSource::Config => out.push_str(&format!(
                    "           suppressed by configuration path `{}` (`rule {}`)\n",
                    suppressed.suppression.path.as_deref().unwrap_or("?"),
                    suppressed.suppression.rules
                )),
                SuppressionSource::Inline => out.push_str(&format!(
                    "           suppressed by {}:{} (`ignore {}`)\n",
                    display_suppression_file(&suppressed.suppression.file),
                    suppressed.suppression.line,
                    suppressed.suppression.rules
                )),
            }
            out.push_str(&format!(
                "           reason: {}\n",
                suppressed
                    .suppression
                    .reason
                    .as_deref()
                    .unwrap_or("(none given)")
            ));
        }
    }

    if !outcome.diagnostics.is_empty() {
        out.push_str(&format!("\n{} diagnostic(s):\n", outcome.diagnostics.len()));
        for diagnostic in &outcome.diagnostics {
            out.push_str(&format!(
                "  - [{}] {}\n",
                diagnostic.code, diagnostic.message
            ));
        }
    }

    out
}

/// Renders a compact terminal report (one line per finding) without color.
pub fn render_terminal_compact(outcome: &ScanOutcome) -> String {
    render_terminal_compact_with_color(outcome, TerminalColor::PLAIN)
}

/// Renders a compact terminal report, optionally with ANSI colors.
pub fn render_terminal_compact_with_color(outcome: &ScanOutcome, color: TerminalColor) -> String {
    let mut out = String::new();
    for finding in &outcome.findings {
        out.push_str(&format!(
            "{} {} {}\n",
            color.severity(finding.severity, finding.severity.as_str()),
            finding.rule_id,
            finding.location.display_label()
        ));
    }
    out.push_str(&summary_line(&outcome.findings));
    if outcome.stats.findings_suppressed > 0 {
        out.push_str(&format!(
            " — {} suppressed",
            outcome.stats.findings_suppressed
        ));
    }
    if let Some(truncation) = outcome.truncation {
        out.push_str(&format!(
            " — {} more finding(s) not shown (--max-findings {})",
            truncation.omitted, truncation.shown
        ));
    }
    out.push('\n');
    out
}

/// Appends the explicit truncation notice used by human-readable reports.
fn append_truncation_notice(outcome: &ScanOutcome, out: &mut String) {
    if let Some(truncation) = outcome.truncation {
        out.push_str(&format!(
            "\n{} more finding(s) not shown (truncated by --max-findings {}).\n",
            truncation.omitted, truncation.shown
        ));
    }
}

/// A serializable JSON report.
#[derive(Debug, Serialize)]
struct JsonReport<'a> {
    schema_version: &'static str,
    tool: ToolInfo,
    project: ProjectSummary,
    stats: StatsSummary,
    /// Effective, serializable configuration used for the scan (#148).
    ///
    /// `ScanConfig` contains only scan settings: it has no environment data,
    /// credentials, or absolute user paths.
    effective_config: &'a ScanConfig,
    /// Present only when the scan was compared against a baseline.
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline: Option<&'a BaselineReport>,
    findings: Vec<FindingJson<'a>>,
    suppressed: &'a [SuppressedFinding],
    suppressions: Vec<SuppressionJson>,
    config_suppressions: &'a [ConfigSuppressionReport],
    diagnostics: &'a [Diagnostic],
    /// Present only when the caller bounded the number of reported findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation: Option<FindingTruncation>,
}

/// A finding in the JSON report, optionally carrying baseline state.
#[derive(Debug, Serialize)]
struct FindingJson<'a> {
    #[serde(flatten)]
    finding: &'a Finding,
    /// Present only when the scan was compared against a baseline.
    #[serde(skip_serializing_if = "Option::is_none")]
    baseline_status: Option<BaselineStatus>,
}

/// Tool identity in JSON reports.
#[derive(Debug, Serialize)]
struct ToolInfo {
    name: &'static str,
    version: &'static str,
    information_uri: &'static str,
}

/// Project summary in JSON reports.
#[derive(Debug, Serialize)]
struct ProjectSummary {
    root: String,
    kind: String,
    source_files: usize,
    soroban_sdk_versions: Vec<String>,
}

/// Scan statistics in JSON reports.
#[derive(Debug, Serialize)]
struct StatsSummary {
    files_analyzed: usize,
    files_parsed: usize,
    files_failed: usize,
    files_skipped: usize,
    rules_run: usize,
    rules_skipped: usize,
    findings_raw: usize,
    findings_rejected: usize,
    suppressions_detected: usize,
    findings_suppressed: usize,
    findings_suppressed_by_config: usize,
    config_suppressions_detected: usize,
    config_suppressions_matched: usize,
    config_suppressions_applied: usize,
    generated_files_marked: usize,
    generated_files_excluded: usize,
    /// Gate findings grouped by stable category name.
    findings_by_category: BTreeMap<String, usize>,
}

/// A detected suppression directive in JSON reports.
#[derive(Debug, Serialize)]
struct SuppressionJson {
    file: String,
    line: usize,
    rules: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    start_line: usize,
    end_line: usize,
    /// True when the directive suppressed at least one finding.
    applied: bool,
}

/// Collects the detected suppression directives for the JSON report.
///
/// Directives that suppressed nothing are included too, so suppression usage
/// stays auditable.
fn suppression_reports(outcome: &ScanOutcome) -> Vec<SuppressionJson> {
    outcome
        .suppressions
        .iter()
        .map(|suppression| {
            let file = suppression.file_label();
            let applied = outcome.suppressed.iter().any(|item| {
                item.suppression.file == file && item.suppression.line == suppression.line
            });
            SuppressionJson {
                file,
                line: suppression.line,
                rules: suppression.targets.label(),
                reason: suppression.reason.clone(),
                start_line: suppression.start_line,
                end_line: suppression.end_line,
                applied,
            }
        })
        .collect()
}
/// Renders the JSON report.
pub fn render_json(outcome: &ScanOutcome) -> Result<String, serde_json::Error> {
    render_json_with_baseline(outcome, None)
}

/// Renders the JSON report with an optional baseline comparison.
pub fn render_json_with_baseline(
    outcome: &ScanOutcome,
    baseline: Option<&BaselineReport>,
) -> Result<String, serde_json::Error> {
    let findings = outcome
        .findings
        .iter()
        .map(|finding| FindingJson {
            finding,
            baseline_status: baseline.and_then(|report| report.status(&finding.fingerprint)),
        })
        .collect();
    let report = JsonReport {
        schema_version: REPORT_SCHEMA_VERSION,
        tool: ToolInfo {
            name: TOOL_NAME,
            version: crate::VERSION,
            information_uri: TOOL_URL,
        },
        project: ProjectSummary {
            root: outcome.project.root.display().to_string(),
            kind: outcome.project.kind.to_string(),
            source_files: outcome.project.source_files,
            soroban_sdk_versions: outcome.project.soroban.sdk_versions.clone(),
        },
        stats: StatsSummary {
            files_analyzed: outcome.stats.files_analyzed,
            files_parsed: outcome.stats.files_parsed,
            files_failed: outcome.stats.files_failed,
            files_skipped: outcome.stats.files_skipped,
            rules_run: outcome.stats.rules_run,
            rules_skipped: outcome.stats.rules_skipped,
            findings_raw: outcome.stats.findings_raw,
            findings_rejected: outcome.stats.findings_rejected,
            suppressions_detected: outcome.stats.suppressions_detected,
            findings_suppressed: outcome.stats.findings_suppressed,
            findings_suppressed_by_config: outcome.stats.findings_suppressed_by_config,
            config_suppressions_detected: outcome.stats.config_suppressions_detected,
            config_suppressions_matched: outcome.stats.config_suppressions_matched,
            config_suppressions_applied: outcome.stats.config_suppressions_applied,
            generated_files_marked: outcome.stats.generated_files_marked,
            generated_files_excluded: outcome.stats.generated_files_excluded,
            findings_by_category: outcome.stats.findings_by_category.clone(),
        },
        effective_config: &outcome.config,
        baseline,
        findings,
        suppressed: &outcome.suppressed,
        suppressions: suppression_reports(outcome),
        config_suppressions: &outcome.config_suppressions,
        diagnostics: &outcome.diagnostics,
        truncation: outcome.truncation,
    };
    serde_json::to_string_pretty(&report)
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

/// Maps a finding severity onto a GitHub workflow-command level.
fn github_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "notice",
    }
}

/// Escapes a value for the message portion of a GitHub workflow command.
///
/// See the workflow-command escaping rules: `%`, carriage returns, and newlines
/// must be percent-encoded so scanned source can never inject a new command.
fn escape_github_data(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escapes a value for the property portion of a GitHub workflow command.
///
/// Properties additionally require `:` and `,` to be escaped.
fn escape_github_property(value: &str) -> String {
    escape_github_data(value)
        .replace(':', "%3A")
        .replace(',', "%2C")
}

/// Renders one GitHub Actions annotation line for a finding.
fn github_annotation(finding: &Finding) -> String {
    let file = finding.location.file.to_string_lossy().replace('\\', "/");
    let mut properties = format!(
        "file={},line={}",
        escape_github_property(&file),
        finding.location.line
    );
    if let Some(column) = finding.location.column {
        properties.push_str(&format!(",col={column}"));
    }
    if let Some(end_line) = finding.location.end_line {
        properties.push_str(&format!(",endLine={end_line}"));
    }
    if let Some(end_column) = finding.location.end_column {
        properties.push_str(&format!(",endColumn={end_column}"));
    }
    properties.push_str(&format!(
        ",title={}",
        escape_github_property(&format!("{}: {}", finding.rule_id, finding.title))
    ));

    let message = escape_github_data(&format!(
        "{}: {} — {}",
        finding.rule_id, finding.title, finding.evidence
    ));
    format!(
        "::{} {}::{}",
        github_level(finding.severity),
        properties,
        message
    )
}

/// Renders GitHub Actions workflow-command annotations, one per finding.
///
/// Only active findings are annotated; findings suppressed by an inline
/// directive stay visible in the other formats but do not fail the gate.
pub fn render_github(outcome: &ScanOutcome) -> String {
    let mut out = String::new();
    for finding in &outcome.findings {
        out.push_str(&github_annotation(finding));
        out.push('\n');
    }
    if let Some(truncation) = outcome.truncation {
        out.push_str(&format!(
            "::notice::{} more finding(s) not shown (--max-findings {})\n",
            truncation.omitted, truncation.shown
        ));
    }
    out
}

/// Builds one SARIF result.
///
/// When `suppression` is set, the result is marked as an in-source
/// suppression (SARIF 2.1.0) instead of being dropped from the report.
fn sarif_result(
    finding: &Finding,
    suppression: Option<&SuppressionInfo>,
    baseline_status: Option<BaselineStatus>,
) -> serde_json::Value {
    use serde_json::json;

    let mut region = json!({ "startLine": finding.location.line });
    if let Some(column) = finding.location.column {
        region["startColumn"] = json!(column);
    }
    if let Some(end_line) = finding.location.end_line {
        region["endLine"] = json!(end_line);
    }
    let mut result = json!({
        "ruleId": finding.rule_id,
        "level": sarif_level(finding.severity),
        "message": { "text": format!("{} — {}", finding.title, finding.evidence) },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": finding.location.file.to_string_lossy().replace('\\', "/")
                },
                "region": region
            }
        }],
        "partialFingerprints": {
            "sorobanScanFingerprint": finding.fingerprint
        },
        "properties": {
            "severity": finding.severity.as_str(),
            "confidence": finding.confidence.as_str(),
            "category": finding.category.as_str(),
            "remediation": finding.remediation
        }
    });

    if let Some(status) = baseline_status {
        result["properties"]["baselineStatus"] = json!(status.as_str());
    }

    if let Some(suppression) = suppression {
        let (kind, suppressed_by, default_reason) = match suppression.source {
            SuppressionSource::Config => (
                "external",
                format!("config:{}", suppression.path.as_deref().unwrap_or_default()),
                "configuration suppression",
            ),
            SuppressionSource::Inline => (
                "inSource",
                format!("{}:{}", suppression.file, suppression.line),
                "inline soroban-scan suppression",
            ),
        };
        let justification = suppression
            .reason
            .clone()
            .unwrap_or_else(|| default_reason.to_string());
        result["suppressions"] = json!([{
            "kind": kind,
            "status": "accepted",
            "justification": justification,
        }]);
        result["properties"]["suppressed"] = json!(true);
        result["properties"]["suppressedBy"] = json!(suppressed_by);
        result["properties"]["suppressedRules"] = json!(suppression.rules);
        result["properties"]["suppressionSource"] = match suppression.source {
            SuppressionSource::Config => json!("config"),
            SuppressionSource::Inline => json!("inline"),
        };
    }

    result
}

/// Renders the SARIF 2.1.0 report.
pub fn render_sarif(outcome: &ScanOutcome, registry: &RuleRegistry) -> String {
    render_sarif_with_baseline(outcome, registry, None)
}

/// Renders the SARIF 2.1.0 report with an optional baseline comparison.
pub fn render_sarif_with_baseline(
    outcome: &ScanOutcome,
    registry: &RuleRegistry,
    baseline: Option<&BaselineReport>,
) -> String {
    use serde_json::{json, Value};

    let rules: Vec<Value> = registry
        .metadata_sorted()
        .iter()
        .map(|meta| {
            let references = if meta.references.is_empty() {
                "No external references.".to_string()
            } else {
                meta.references
                    .iter()
                    .map(|reference| format!("- {reference}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            let help_markdown = format!(
                "## {}\n\n{}\n\n### Remediation\n\n{}\n\n### References\n\n{}",
                meta.title, meta.description, meta.remediation, references
            );
            json!({
                "id": meta.id,
                "name": meta.title,
                "shortDescription": { "text": meta.title },
                "fullDescription": { "text": meta.description },
                "help": {
                    "text": format!("{}\n\nRemediation: {}", meta.description, meta.remediation),
                    "markdown": help_markdown
                },
                "helpUri": meta.references.first().copied().unwrap_or(TOOL_URL),
                "defaultConfiguration": { "level": sarif_level(meta.default_severity) },
                "properties": {
                    "category": meta.category.as_str(),
                    "confidence": meta.default_confidence.as_str(),
                    "severity": meta.default_severity.as_str(),
                    "remediation": meta.remediation,
                    "references": meta.references
                }
            })
        })
        .collect();

    let mut results: Vec<Value> = outcome
        .findings
        .iter()
        .map(|finding| {
            sarif_result(
                finding,
                None,
                baseline.and_then(|report| report.status(&finding.fingerprint)),
            )
        })
        .collect();

    // Suppressed findings are never dropped: they stay in the SARIF results and
    // are marked as in-source suppressions (SARIF 2.1.0 `suppressions`).
    results.extend(
        outcome.suppressed.iter().map(|suppressed| {
            sarif_result(&suppressed.finding, Some(&suppressed.suppression), None)
        }),
    );

    let mut run = json!({
        "tool": {
            "driver": {
                "name": TOOL_NAME,
                "version": crate::VERSION,
                "informationUri": TOOL_URL,
                "rules": rules
            }
        },
        "results": results
    });

    let mut run_properties = serde_json::Map::new();
    if let Some(truncation) = outcome.truncation {
        run_properties.insert(
            "truncation".to_string(),
            serde_json::to_value(truncation).unwrap_or(Value::Null),
        );
        run["invocations"] = json!([{
            "executionSuccessful": true,
            "toolExecutionNotifications": [{
                "level": "note",
                "message": {
                    "text": format!(
                        "{} more finding(s) not shown (--max-findings {})",
                        truncation.omitted, truncation.shown
                    )
                }
            }]
        }]);
    }
    if let Some(baseline) = baseline {
        run_properties.insert(
            "baseline".to_string(),
            serde_json::to_value(baseline).unwrap_or(Value::Null),
        );
    }
    if !run_properties.is_empty() {
        run["properties"] = Value::Object(run_properties);
    }

    let document = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run]
    });

    serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
}

/// Renders the Markdown report.
pub fn render_markdown(outcome: &ScanOutcome) -> String {
    let counts = severity_counts(&outcome.findings);
    let mut out = String::new();
    out.push_str("# Soroban Security Scan\n\n");
    out.push_str(&format!("- **Tool:** {TOOL_NAME} {}\n", crate::VERSION));
    out.push_str(&format!(
        "- **Project:** `{}` ({})\n",
        outcome.project.root.display(),
        outcome.project.kind
    ));
    out.push_str(&format!(
        "- **Files analyzed:** {}\n",
        outcome.stats.files_analyzed
    ));
    out.push_str(&format!("- **Findings:** {}\n\n", outcome.findings.len()));
    out.push_str(&format!(
        "- **Suppressed (excluded from the gate):** {} ({} inline, {} by configuration)\n",
        outcome.stats.findings_suppressed,
        outcome
            .stats
            .findings_suppressed
            .saturating_sub(outcome.stats.findings_suppressed_by_config),
        outcome.stats.findings_suppressed_by_config
    ));
    out.push_str(&format!(
        "- **Generated code:** {} marked, {} excluded\n",
        outcome.stats.generated_files_marked, outcome.stats.generated_files_excluded
    ));
    out.push_str(&format!(
        "- **Configured suppressions:** {} detected, {} matched, {} applied\n\n",
        outcome.stats.config_suppressions_detected,
        outcome.stats.config_suppressions_matched,
        outcome.stats.config_suppressions_applied
    ));

    out.push_str("## Summary\n\n");
    out.push_str("| Severity | Count |\n| -------- | ----- |\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        out.push_str(&format!(
            "| {} | {} |\n",
            severity,
            counts[severity.rank() as usize]
        ));
    }
    out.push('\n');

    if !outcome.findings.is_empty() {
        out.push_str("## Top rules\n\n");
        out.push_str("| Rule | Count |\n| ---- | ----- |\n");
        for (rule, count) in rule_counts(&outcome.findings) {
            out.push_str(&format!("| {rule} | {count} |\n"));
        }
        out.push('\n');

        out.push_str("## Categories\n\n");
        out.push_str("| Category | Count |\n| -------- | ----- |\n");
        for (category, count) in category_counts(&outcome.findings) {
            out.push_str(&format!("| {category} | {count} |\n"));
        }
        out.push('\n');
    }

    if outcome.findings.is_empty() {
        if outcome.truncation.is_none() {
            out.push_str("No security findings.\n");
        }
        append_markdown_truncation(outcome, &mut out);
        append_markdown_suppressed(outcome, &mut out);
        return out;
    }

    out.push_str("## Findings\n\n");
    append_markdown_truncation(outcome, &mut out);
    for finding in &outcome.findings {
        out.push_str(&format!("### {} — {}\n\n", finding.rule_id, finding.title));
        out.push_str(&format!("- **Severity:** {}\n", finding.severity));
        out.push_str(&format!("- **Confidence:** {}\n", finding.confidence));
        out.push_str(&format!("- **Category:** {}\n", finding.category));
        out.push_str(&format!(
            "- **Location:** `{}`\n",
            finding.location.display_label()
        ));
        out.push_str(&format!("- **Evidence:** {}\n", finding.evidence));
        out.push_str(&format!("- **Remediation:** {}\n", finding.remediation));
        if !finding.references.is_empty() {
            out.push_str("- **References:**\n");
            for reference in &finding.references {
                out.push_str(&format!("  - <{reference}>\n"));
            }
        }
        out.push('\n');
    }
    append_markdown_suppressed(outcome, &mut out);
    out
}

/// Appends the explicit truncation notice to a Markdown report.
fn append_markdown_truncation(outcome: &ScanOutcome, out: &mut String) {
    if let Some(truncation) = outcome.truncation {
        out.push_str(&format!(
            "> **Truncated:** {} more finding(s) not shown \
             (`--max-findings {}`).\n\n",
            truncation.omitted, truncation.shown
        ));
    }
}

/// Appends the suppressed-findings section to a Markdown report.
///
/// Suppressed findings are excluded from the gate but never dropped from the
/// report.
fn append_markdown_suppressed(outcome: &ScanOutcome, out: &mut String) {
    if outcome.suppressed.is_empty() {
        return;
    }
    out.push_str("\n## Suppressed findings\n\n");
    out.push_str("Suppressed findings are excluded from the gate and always reported:\n\n");
    for suppressed in &outcome.suppressed {
        let by = match suppressed.suppression.source {
            SuppressionSource::Config => format!(
                "configuration path `{}` (`rule {}`)",
                suppressed.suppression.path.as_deref().unwrap_or("?"),
                suppressed.suppression.rules
            ),
            SuppressionSource::Inline => format!(
                "`{}:{}` (`ignore {}`)",
                display_suppression_file(&suppressed.suppression.file),
                suppressed.suppression.line,
                suppressed.suppression.rules
            ),
        };
        out.push_str(&format!(
            "- **{}** `{}` at `{}` — suppressed by {}\n",
            suppressed.finding.rule_id,
            suppressed.finding.title,
            suppressed.finding.location.display_label(),
            by
        ));
        out.push_str(&format!(
            "  - Reason: {}\n",
            suppressed
                .suppression
                .reason
                .as_deref()
                .unwrap_or("(none given)")
        ));
    }

    if !outcome.config_suppressions.is_empty() {
        out.push_str("\n### Configured suppressions\n\n");
        out.push_str("| Path | Rule | Matched | Suppressed | Applied | Reason |\n");
        out.push_str("| ---- | ---- | ------- | ---------- | ------- | ------ |\n");
        for suppression in &outcome.config_suppressions {
            out.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} |\n",
                suppression.path,
                suppression.rule,
                suppression.matched,
                suppression.findings_suppressed,
                suppression.applied,
                suppression.reason.as_deref().unwrap_or("")
            ));
        }
    }
}

/// Escapes text for HTML text and quoted-attribute contexts.
///
/// Every source-derived value in an HTML report passes through this function.
/// The report never interpolates raw finding text into markup.
fn escape_html(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Inline stylesheet used by the self-contained HTML report.
///
/// No external fonts, stylesheets, scripts, or images are referenced, so the
/// file renders identically offline and is safe for a strict CSP.
const HTML_STYLE: &str = "\
:root{color-scheme:light dark;--bg:#f7f8fa;--panel:#fff;--ink:#1c2430;--muted:#5b6776;\
--line:#d8dee7;--critical:#8b1a1a;--high:#b3401b;--medium:#8a6100;--low:#145c8a;--info:#3f4a5a}\
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);\
font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}\
main{max-width:1040px;margin:0 auto;padding:2rem 1.25rem 4rem}h1{font-size:1.65rem;margin:0 0 .35rem}\
h2{font-size:1.15rem;margin:2rem 0 .6rem;border-bottom:1px solid var(--line);padding-bottom:.35rem}\
.meta{color:var(--muted);margin:.2rem 0}.cards{display:grid;gap:.6rem;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));margin:1rem 0}\
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.7rem .8rem}\
.card .label{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}\
.card .value{font-size:1.35rem;font-weight:650}\
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:8px;overflow:hidden}\
th,td{text-align:left;padding:.5rem .65rem;border-bottom:1px solid var(--line);vertical-align:top}\
th{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}\
tr:last-child td{border-bottom:0}\
.finding{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--muted);border-radius:8px;padding:1rem;margin:.8rem 0}\
.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}\
.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}\
.finding.info{border-left-color:var(--info)}\
.finding h3{margin:0 0 .45rem;font-size:1.05rem}.finding h3 .rule{color:var(--muted);font-weight:500}\
.badge{display:inline-block;border:1px solid currentColor;border-radius:999px;padding:.05rem .5rem;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}\
dl{display:grid;grid-template-columns:max-content 1fr;gap:.15rem .7rem;margin:.55rem 0}\
dt{color:var(--muted)}dd{margin:0}\
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:.6rem;margin:.35rem 0}\
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.9em}\
ul.references{margin:.3rem 0 0;padding-left:1.1rem}.note{color:var(--muted);font-style:italic}\
@media (prefers-color-scheme:dark){:root{--bg:#12161c;--panel:#1a2028;--ink:#e6eaf0;--muted:#a3adba;--line:#2c3541}}\
@media print{@page{margin:18mm}:root{color-scheme:light;--bg:#fff;--panel:#fff;--ink:#000;--muted:#333;--line:#999}\
*{print-color-adjust:exact;-webkit-print-color-adjust:exact}body{background:#fff;color:#000;font-size:11pt}\
main{max-width:none;padding:0}a{color:inherit;text-decoration:none}\
h1,h2{break-after:avoid}.cards{grid-template-columns:repeat(5,1fr)}\
.card,.finding,table,pre{break-inside:avoid}.finding{box-shadow:none}tr,img{break-inside:avoid}\
thead{display:table-header-group}}\
";

/// Renders a self-contained HTML report.
///
/// The document inlines its CSS and contains no JavaScript or remote resources.
/// All finding, project, and suppression text is escaped, so crafted evidence
/// or source paths cannot inject markup.
pub fn render_html(outcome: &ScanOutcome) -> String {
    render_html_with_policy(outcome, None)
}

/// Renders a self-contained HTML report with an explicit gate status.
///
/// `gate` is the severity threshold used by `--fail-on`, when one applies.
/// The gate is evaluated against the reported findings only: suppressed
/// findings are excluded, matching the `--fail-on` contract. The document
/// inlines its CSS (including a deterministic `@media print` stylesheet) and
/// contains no JavaScript or remote resources, so it prints and renders with
/// the network disabled.
pub fn render_html_with_policy(outcome: &ScanOutcome, gate: Option<Severity>) -> String {
    let counts = severity_counts(&outcome.findings);
    let gate_findings = gate.map(|threshold| {
        outcome
            .findings
            .iter()
            .filter(|finding| finding.severity.meets(threshold))
            .count()
    });
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str("<title>Soroban Security Scan</title>\n<style>");
    out.push_str(HTML_STYLE);
    out.push_str("</style>\n</head>\n<body>\n<main>\n");
    out.push_str("<h1>Soroban Security Scan</h1>\n");
    out.push_str(&format!(
        "<p class=\"meta\"><strong>{}</strong> {} &middot; Project <code>{}</code> ({}) &middot; \
         Files analyzed: {}</p>\n",
        TOOL_NAME,
        crate::VERSION,
        escape_html(&outcome.project.root.display().to_string()),
        escape_html(&outcome.project.kind.to_string()),
        outcome.stats.files_analyzed
    ));

    out.push_str("<div class=\"cards\">\n");
    for severity in [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ] {
        out.push_str(&format!(
            "<div class=\"card\"><div class=\"label\">{}</div><div class=\"value\">{}</div></div>\n",
            severity,
            counts[severity.rank() as usize]
        ));
    }
    out.push_str("</div>\n");
    out.push_str(&format!(
        "<p class=\"meta\">{} finding(s) &middot; {} suppressed (excluded from the gate)</p>\n",
        outcome.findings.len(),
        outcome.stats.findings_suppressed
    ));
    out.push_str("<h2>Policy status</h2>\n");
    match (gate, gate_findings) {
        (Some(threshold), Some(count)) => {
            let status = if count > 0 { "fail" } else { "pass" };
            out.push_str(&format!(
                "<p class=\"meta\">Gate threshold <code>{}</code>: <strong>{status}</strong> \
                 &middot; {} finding(s) at or above the threshold</p>\n",
                threshold, count
            ));
        }
        _ => {
            out.push_str(
                "<p class=\"meta\">Gate: <strong>not evaluated</strong> \
                 (no policy threshold supplied)</p>\n",
            );
        }
    }

    if outcome.findings.is_empty() {
        out.push_str("<h2>Findings</h2>\n<p class=\"note\">No security findings.</p>\n");
    } else {
        out.push_str("<h2>Summary</h2>\n<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>\n");
        for severity in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{}</td></tr>\n",
                severity,
                counts[severity.rank() as usize]
            ));
        }
        out.push_str("</tbody></table>\n");

        out.push_str("<h2>Top rules</h2>\n<table><thead><tr><th>Rule</th><th>Count</th></tr></thead><tbody>\n");
        for (rule, count) in rule_counts(&outcome.findings) {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td>{count}</td></tr>\n",
                escape_html(&rule)
            ));
        }
        out.push_str("</tbody></table>\n");

        out.push_str("<h2>Categories</h2>\n<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>\n");
        for (category, count) in category_counts(&outcome.findings) {
            out.push_str(&format!(
                "<tr><td>{}</td><td>{count}</td></tr>\n",
                escape_html(category)
            ));
        }
        out.push_str("</tbody></table>\n");
    }

    append_html_truncation(outcome, &mut out);

    if !outcome.findings.is_empty() {
        out.push_str("<h2>Findings</h2>\n");
        for finding in &outcome.findings {
            out.push_str(&format!(
                "<article class=\"finding {}\">\n<h3><span class=\"rule\">{} &middot;</span> {}</h3>\n",
                finding.severity.as_str(),
                escape_html(&finding.rule_id),
                escape_html(&finding.title)
            ));
            let gate_badge = match gate {
                Some(threshold) if finding.severity.meets(threshold) => {
                    "<span class=\"badge\">above gate</span> "
                }
                Some(_) => "<span class=\"badge\">below gate</span> ",
                None => "",
            };
            out.push_str(&format!(
                "<p><span class=\"badge\">{}</span> <span class=\"badge\">{}</span> <span class=\"badge\">{}</span> {}</p>\n",
                escape_html(&finding.severity.to_string()),
                escape_html(&finding.confidence.to_string()),
                escape_html(finding.category.as_str()),
                gate_badge
            ));
            out.push_str(&format!(
                "<dl><dt>Location</dt><dd><code>{}</code></dd>\n",
                escape_html(&finding.location.display_label())
            ));
            out.push_str(&format!(
                "<dt>Description</dt><dd>{}</dd></dl>\n",
                escape_html(&finding.description)
            ));
            out.push_str(&format!(
                "<p><strong>Evidence</strong></p><pre><code>{}</code></pre>\n",
                escape_html(&finding.evidence)
            ));
            out.push_str(&format!(
                "<p><strong>Remediation</strong></p><p>{}</p>\n",
                escape_html(&finding.remediation)
            ));
            if !finding.references.is_empty() {
                out.push_str("<p><strong>References</strong></p><ul class=\"references\">\n");
                for reference in &finding.references {
                    out.push_str(&format!(
                        "<li><code>{}</code></li>\n",
                        escape_html(reference)
                    ));
                }
                out.push_str("</ul>\n");
            }
            out.push_str("</article>\n");
        }
    }

    append_html_suppressed(outcome, &mut out);
    out.push_str("</main>\n</body>\n</html>\n");
    out
}

/// Appends the explicit truncation notice to an HTML report.
fn append_html_truncation(outcome: &ScanOutcome, out: &mut String) {
    if let Some(truncation) = outcome.truncation {
        out.push_str(&format!(
            "<p class=\"note\">Truncated: {} more finding(s) not shown (--max-findings {}).</p>\n",
            truncation.omitted, truncation.shown
        ));
    }
}

/// Appends the suppressed-findings section to an HTML report.
fn append_html_suppressed(outcome: &ScanOutcome, out: &mut String) {
    if outcome.suppressed.is_empty() {
        return;
    }
    out.push_str("<h2>Suppressed findings</h2>\n");
    out.push_str(
        "<p class=\"note\">Suppressed findings are excluded from the gate and always reported.</p>\n",
    );
    out.push_str("<table><thead><tr><th>Finding</th><th>Location</th><th>Suppressed by</th><th>Reason</th></tr></thead><tbody>\n");
    for suppressed in &outcome.suppressed {
        out.push_str(&format!(
            "<tr><td><code>{}</code> {}</td><td><code>{}</code></td><td><code>{}:{}</code> \
             (<code>ignore {}</code>)</td><td>{}</td></tr>\n",
            escape_html(&suppressed.finding.rule_id),
            escape_html(&suppressed.finding.title),
            escape_html(&suppressed.finding.location.display_label()),
            escape_html(&display_suppression_file(&suppressed.suppression.file)),
            suppressed.suppression.line,
            escape_html(&suppressed.suppression.rules),
            escape_html(
                suppressed
                    .suppression
                    .reason
                    .as_deref()
                    .unwrap_or("(none given)")
            )
        ));
    }
    out.push_str("</tbody></table>\n");
}

/// Renders the rule catalog for `soroban-scan rules`.
pub fn render_rule_list(metas: &[&RuleMetadata], format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => {
            let items: Vec<_> = metas
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "id": m.id,
                        "title": m.title,
                        "category": m.category.as_str(),
                        "severity": m.default_severity.as_str(),
                        "confidence": m.default_confidence.as_str(),
                    })
                })
                .collect();
            serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string())
        }
        OutputFormat::Markdown => {
            let mut out = String::new();
            out.push_str("| Rule | Title | Severity | Confidence | Category |\n");
            out.push_str("| ---- | ----- | -------- | ---------- | -------- |\n");
            for meta in metas {
                out.push_str(&format!(
                    "| [{}](detectors/{}.md) | {} | {} | {} | {} |\n",
                    meta.id,
                    meta.id,
                    meta.title,
                    meta.default_severity,
                    meta.default_confidence,
                    meta.category
                ));
            }
            out
        }
        _ => {
            let mut out = String::new();
            out.push_str(&format!(
                "{:<8} {:<8} {:<10} {}\n",
                "RULE", "SEVERITY", "CONFIDENCE", "TITLE"
            ));
            for meta in metas {
                out.push_str(&format!(
                    "{:<8} {:<8} {:<10} {}\n",
                    meta.id,
                    meta.default_severity.as_str(),
                    meta.default_confidence.as_str(),
                    meta.title
                ));
            }
            out
        }
    }
}

/// Renders a single rule for `soroban-scan explain`.
pub fn render_rule_detail(meta: &RuleMetadata, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "id": meta.id,
            "title": meta.title,
            "description": meta.description,
            "category": meta.category.as_str(),
            "severity": meta.default_severity.as_str(),
            "confidence": meta.default_confidence.as_str(),
            "remediation": meta.remediation,
            "references": meta.references,
        }))
        .unwrap_or_else(|_| "{}".to_string()),
        OutputFormat::Markdown => format!(
            "# {} — {}\n\n- **Severity:** {}\n- **Confidence:** {}\n- **Category:** {}\n\n\
## Description\n\n{}\n\n## Remediation\n\n{}\n\n## References\n\n{}\n",
            meta.id,
            meta.title,
            meta.default_severity,
            meta.default_confidence,
            meta.category,
            meta.description,
            meta.remediation,
            meta.references
                .iter()
                .map(|r| format!("- <{r}>"))
                .collect::<Vec<_>>()
                .join("\n")
        ),
        _ => {
            let mut out = String::new();
            out.push_str(&format!("{} — {}\n\n", meta.id, meta.title));
            out.push_str(&format!("Severity:   {}\n", meta.default_severity));
            out.push_str(&format!("Confidence: {}\n", meta.default_confidence));
            out.push_str(&format!("Category:   {}\n\n", meta.category));
            out.push_str(&format!("{}\n\n", meta.description));
            out.push_str(&format!("Remediation:\n{}\n\n", meta.remediation));
            out.push_str("References:\n");
            for reference in meta.references {
                out.push_str(&format!("  - {reference}\n"));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::confidence::Confidence;
    use crate::config::ScanConfig;
    use crate::engine;
    use crate::severity::Severity;

    fn sample() -> (ScanOutcome, RuleRegistry) {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/corpus/SS-001/positive.rs"
        ))
        .unwrap();
        let registry = RuleRegistry::with_default_rules();
        let outcome =
            engine::scan_source_str(&src, "positive.rs", &ScanConfig::default(), &registry);
        (outcome, registry)
    }

    #[test]
    fn json_report_includes_the_effective_configuration() {
        let (mut outcome, _) = sample();
        outcome.config.min_severity = Severity::Medium;
        outcome.config.min_confidence = Confidence::High;
        outcome.config.exclude = vec!["vendor/**".into()];
        outcome.config.rules.disabled = vec!["SS-007".into()];
        outcome.config.rules.enabled = vec!["SS-001".into()];
        outcome
            .config
            .rules
            .severity_overrides
            .insert("SS-001".into(), Severity::Critical);
        outcome
            .config
            .rules
            .confidence_overrides
            .insert("SS-001".into(), Confidence::High);

        let text = render_json(&outcome).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let effective = &value["effective_config"];

        assert_eq!(effective["min_severity"], "medium");
        assert_eq!(effective["min_confidence"], "high");
        assert_eq!(effective["exclude"][0], "vendor/**");
        assert_eq!(effective["rules"]["disabled"][0], "SS-007");
        assert_eq!(effective["rules"]["enabled"][0], "SS-001");
        assert_eq!(
            effective["rules"]["severity_overrides"]["SS-001"],
            "critical"
        );
        assert_eq!(effective["rules"]["confidence_overrides"]["SS-001"], "high");
        // No environment data or secret-bearing fields are serialized.
        assert!(effective.get("environment").is_none());
        assert!(effective.get("secrets").is_none());
    }

    #[test]
    fn json_report_includes_an_empty_configuration_by_default() {
        let (outcome, _) = sample();
        let value: serde_json::Value =
            serde_json::from_str(&render_json(&outcome).unwrap()).unwrap();
        let effective = &value["effective_config"];

        assert_eq!(effective["min_severity"], "info");
        assert_eq!(effective["min_confidence"], "low");
        assert_eq!(effective["follow_symlinks"], false);
        assert!(effective["rules"]["disabled"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn terminal_report_contains_findings() {
        let (outcome, _) = sample();
        let text = render_terminal(&outcome);
        assert!(text.contains("SS-001"));
        assert!(text.contains("finding(s)"));
    }

    #[test]
    fn json_report_is_valid_and_has_findings() {
        let (outcome, _) = sample();
        let text = render_json(&outcome).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["tool"]["name"], "soroban-scan");
        assert!(!value["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn json_report_exposes_the_stable_contract() {
        let (outcome, _) = sample();
        let text = render_json(&outcome).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["schema_version"], REPORT_SCHEMA_VERSION);
        for key in [
            "schema_version",
            "tool",
            "project",
            "stats",
            "effective_config",
            "findings",
            "diagnostics",
        ] {
            assert!(value.get(key).is_some(), "missing top-level key: {key}");
        }
        let finding = &value["findings"][0];
        for key in [
            "rule_id",
            "title",
            "severity",
            "confidence",
            "category",
            "location",
            "evidence",
            "remediation",
            "fingerprint",
        ] {
            assert!(finding.get(key).is_some(), "finding missing key: {key}");
        }
    }

    #[test]
    fn json_report_includes_baseline_status_and_counts() {
        use crate::baseline::{self, Baseline, BaselineEntry};

        let (mut outcome, _) = sample();
        let mut extra = outcome.findings[0].clone();
        extra.fingerprint = "extra-new-fingerprint".to_string();
        outcome.findings.push(extra);

        let mut baseline = Baseline::from_findings(&outcome.findings[..outcome.findings.len() - 1]);
        baseline.findings.push(BaselineEntry {
            fingerprint: "resolved-fingerprint".to_string(),
            rule_id: "SS-001".to_string(),
            file: "src/gone.rs".to_string(),
            severity: Severity::High,
            title: "Gone".to_string(),
        });

        let comparison = baseline::compare(&outcome.findings, &baseline);
        let report = BaselineReport::from_comparison(&outcome.findings, &comparison, true);

        let text = render_json_with_baseline(&outcome, Some(&report)).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["baseline"]["new"], 1);
        assert_eq!(value["baseline"]["resolved"], 1);
        assert_eq!(
            value["baseline"]["existing"].as_u64().unwrap() as usize,
            outcome.findings.len() - 1
        );
        assert_eq!(
            value["baseline"]["resolved_findings"][0]["fingerprint"],
            "resolved-fingerprint"
        );

        let findings = value["findings"].as_array().unwrap();
        assert_eq!(findings.len(), outcome.findings.len());
        assert_eq!(findings.last().unwrap()["baseline_status"], "new");
        assert!(findings[..findings.len() - 1]
            .iter()
            .all(|finding| finding["baseline_status"] == "existing"));
    }

    #[test]
    fn json_report_omits_baseline_fields_without_a_baseline() {
        let (outcome, _) = sample();
        let text = render_json(&outcome).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert!(value.get("baseline").is_none());
        for finding in value["findings"].as_array().unwrap() {
            assert!(finding.get("baseline_status").is_none());
        }
    }

    #[test]
    fn sarif_report_maps_baseline_status_into_properties() {
        use crate::baseline::{self, Baseline};

        let (mut outcome, registry) = sample();
        let mut extra = outcome.findings[0].clone();
        extra.fingerprint = "extra-new-fingerprint".to_string();
        outcome.findings.push(extra);

        let baseline = Baseline::from_findings(&outcome.findings[..outcome.findings.len() - 1]);
        let comparison = baseline::compare(&outcome.findings, &baseline);
        let report = BaselineReport::from_comparison(&outcome.findings, &comparison, true);

        let text = render_sarif_with_baseline(&outcome, &registry, Some(&report));
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(value["runs"][0]["properties"]["baseline"]["new"], 1);
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.last().unwrap()["properties"]["baselineStatus"],
            "new"
        );
        assert!(results[..results.len() - 1]
            .iter()
            .all(|result| result["properties"]["baselineStatus"] == "existing"));
    }

    #[test]
    fn sarif_report_is_valid_sarif() {
        let (outcome, registry) = sample();
        let text = render_sarif(&outcome, &registry);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["version"], "2.1.0");
        assert_eq!(value["runs"][0]["tool"]["driver"]["name"], "soroban-scan");
        assert!(!value["runs"][0]["results"].as_array().unwrap().is_empty());
        // Every result must have a rule id and a location.
        for result in value["runs"][0]["results"].as_array().unwrap() {
            assert!(result["ruleId"].is_string());
            assert!(
                result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].is_string()
            );
        }

        // Rule descriptors carry help markdown and remediation metadata for
        // GitHub code scanning (issue #60).
        let rules = value["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap();
        assert!(!rules.is_empty());
        for rule in rules {
            assert!(rule["help"]["text"].is_string());
            let help = rule["help"]["markdown"].as_str().unwrap();
            assert!(help.contains("## "));
            assert!(help.contains("### Remediation"));
            assert!(help.contains("### References"));
            assert!(!rule["properties"]["remediation"]
                .as_str()
                .unwrap()
                .is_empty());
            assert!(rule["properties"]["references"].is_array());
        }
    }

    #[test]
    fn markdown_report_contains_table() {
        let (outcome, _) = sample();
        let text = render_markdown(&outcome);
        assert!(text.contains("| Severity | Count |"));
        assert!(text.contains("SS-001"));
    }

    #[test]
    fn markdown_report_includes_top_rules_and_categories() {
        let (outcome, _) = sample();
        let text = render_markdown(&outcome);
        assert!(text.contains("## Top rules"));
        assert!(text.contains("| Rule | Count |"));
        assert!(text.contains("## Categories"));
        assert!(text.contains("| Category | Count |"));
        assert!(text.contains("| SS-001 |"));
    }

    fn synthetic_finding(rule: &'static str, category: crate::category::Category) -> Finding {
        let meta = crate::rule::RuleMetadata::new(
            rule,
            "Title",
            "Description",
            category,
            Severity::Low,
            Confidence::Low,
            "Remediation",
        );
        Finding::new(
            &meta,
            crate::finding::SourceLocation::new("src/lib.rs", 1),
            "evidence",
        )
    }

    #[test]
    fn markdown_summary_counts_sort_by_count_then_id() {
        use crate::category::Category;

        let findings = vec![
            synthetic_finding("SS-002", Category::Storage),
            synthetic_finding("SS-001", Category::Authorization),
            synthetic_finding("SS-002", Category::Authorization),
            synthetic_finding("SS-001", Category::Authorization),
            synthetic_finding("SS-003", Category::Storage),
        ];

        assert_eq!(
            rule_counts(&findings),
            vec![
                ("SS-001".to_string(), 2),
                ("SS-002".to_string(), 2),
                ("SS-003".to_string(), 1),
            ]
        );
        assert_eq!(
            category_counts(&findings),
            vec![("authorization", 3), ("storage", 2)]
        );
    }

    #[test]
    fn rules_markdown_uses_the_docs_table_format() {
        let registry = RuleRegistry::with_default_rules();
        let text = render_rule_list(&registry.metadata_sorted(), OutputFormat::Markdown);
        assert!(text.starts_with(
            "| Rule | Title | Severity | Confidence | Category |\n\
             | ---- | ----- | -------- | ---------- | -------- |\n"
        ));
        assert!(text.contains(
            "| [SS-001](detectors/SS-001.md) | State-changing entry point without caller authorization | high | medium | authorization |"
        ));
    }

    #[test]
    fn output_format_parsing() {
        assert_eq!(OutputFormat::parse("SARIF").unwrap(), OutputFormat::Sarif);
        assert_eq!(OutputFormat::parse("md").unwrap(), OutputFormat::Markdown);
        assert_eq!(OutputFormat::parse("html").unwrap(), OutputFormat::Html);
        assert_eq!(OutputFormat::parse("github").unwrap(), OutputFormat::Github);
        assert_eq!(OutputFormat::Html.as_str(), "html");
        assert_eq!(OutputFormat::Github.as_str(), "github");
        assert!(OutputFormat::parse("xml").is_err());
    }

    #[test]
    fn html_report_is_self_contained_and_escapes_injection() {
        let (mut outcome, _) = sample();
        assert!(!outcome.findings.is_empty(), "fixture needs a finding");
        outcome.project.root = std::path::PathBuf::from("<svg onload=alert(0)>");
        outcome.findings[0].rule_id = "SS-<script>alert(1)</script>".to_string();
        outcome.findings[0].title = "<img src=x onerror=alert(2)>".to_string();
        outcome.findings[0].evidence = "<script>steal()</script> & \"quoted\" 'single'".to_string();
        outcome.findings[0].remediation = "</pre><iframe src=//evil.test></iframe>".to_string();

        let html = render_html(&outcome);

        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<style>"));
        assert!(html.ends_with("</html>\n"));

        // No source-derived markup survives.
        assert!(!html.contains("<script"));
        assert!(!html.contains("<img"));
        assert!(!html.contains("<svg"));
        assert!(!html.contains("<iframe"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("&lt;img src=x onerror=alert(2)&gt;"));
        assert!(html.contains("&amp; &quot;quoted&quot; &#39;single&#39;"));

        // No remote resources or scripts are referenced.
        assert!(!html.contains("<link"));
        assert!(!html.contains("src=\"http"));
        assert!(!html.contains("@import"));
    }

    #[test]
    fn html_report_handles_the_empty_state() {
        let (mut outcome, _) = sample();
        outcome.findings.clear();
        let html = render_html(&outcome);
        assert!(html.contains("No security findings."));
    }

    #[test]
    fn github_annotations_use_severity_levels_and_locations() {
        let (outcome, _) = sample();
        let text = render_github(&outcome);
        assert!(text.contains("::error file="), "got: {text}");
        assert!(text.contains("line="), "got: {text}");
        assert!(text.contains("title=SS-001"), "got: {text}");
        assert!(text.contains("SS-001:"), "got: {text}");
        assert_eq!(text.lines().count(), outcome.findings.len());
    }

    #[test]
    fn github_workflow_commands_escape_untrusted_text() {
        assert_eq!(escape_github_data("100%\r\nnext"), "100%25%0D%0Anext");
        assert_eq!(escape_github_property("src/a:b,c.rs"), "src/a%3Ab%2Cc.rs");
        // Severity determines the workflow-command level.
        assert_eq!(github_level(Severity::Critical), "error");
        assert_eq!(github_level(Severity::High), "error");
        assert_eq!(github_level(Severity::Medium), "warning");
        assert_eq!(github_level(Severity::Low), "notice");
        assert_eq!(github_level(Severity::Info), "notice");
    }
    struct FixedLineRule {
        meta: crate::rule::RuleMetadata,
        line: usize,
    }

    impl crate::rule::Rule for FixedLineRule {
        fn metadata(&self) -> &crate::rule::RuleMetadata {
            &self.meta
        }

        fn analyze(&self, ctx: &crate::context::AnalysisContext<'_>, out: &mut Vec<Finding>) {
            if let Some(source) = ctx.sources().first() {
                let location =
                    crate::finding::SourceLocation::new(ctx.relative_path(&source.path), self.line);
                out.push(Finding::new(&self.meta, location, "fixture evidence"));
            }
        }
    }

    /// A sample whose only finding is suppressed by an inline directive.
    fn suppressed_sample() -> (ScanOutcome, RuleRegistry) {
        let src = "// soroban-scan: ignore SS-001 -- reviewed by the security team\nfn a() {}\n";
        let mut registry = RuleRegistry::new();
        let meta = crate::rule::RuleMetadata::new(
            "SS-001",
            "Suppressed rule",
            "fixture rule",
            crate::category::Category::Authorization,
            Severity::High,
            crate::confidence::Confidence::High,
            "fix it",
        );
        registry
            .register(Box::new(FixedLineRule { meta, line: 2 }))
            .unwrap();
        let outcome = engine::scan_source_str(src, "src/lib.rs", &ScanConfig::default(), &registry);
        (outcome, registry)
    }

    #[test]
    fn terminal_report_surfaces_suppressed_findings() {
        let (outcome, _) = suppressed_sample();
        let text = render_terminal(&outcome);
        assert!(text.contains("Suppressions: 1"));
        assert!(text.contains("1 suppressed finding(s)"));
        assert!(text.contains("reviewed by the security team"));
        assert!(text.contains("No security findings."));
    }

    #[test]
    fn compact_report_surfaces_the_suppressed_count() {
        let (outcome, _) = suppressed_sample();
        let text = render_terminal_compact(&outcome);
        assert!(text.contains("1 suppressed"), "got: {text}");
    }

    #[test]
    fn json_report_exposes_suppressed_findings_and_counts() {
        let (outcome, _) = suppressed_sample();
        let text = render_json(&outcome).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["stats"]["suppressions_detected"], 1);
        assert_eq!(value["stats"]["findings_suppressed"], 1);
        assert!(value["findings"].as_array().unwrap().is_empty());
        assert_eq!(value["suppressed"][0]["rule_id"], "SS-001");
        assert_eq!(value["suppressed"][0]["location"]["line"], 2);
        assert_eq!(value["suppressed"][0]["suppression"]["file"], "src/lib.rs");
        assert_eq!(value["suppressed"][0]["suppression"]["line"], 1);
        assert_eq!(value["suppressed"][0]["suppression"]["rules"], "SS-001");
        assert_eq!(
            value["suppressed"][0]["suppression"]["reason"],
            "reviewed by the security team"
        );
        assert_eq!(value["suppressions"][0]["applied"], true);
        assert_eq!(value["suppressions"][0]["rules"], "SS-001");
    }

    #[test]
    fn json_report_lists_unapplied_suppressions() {
        let src = "// soroban-scan: ignore SS-002\nfn a() {}\n";
        let mut registry = RuleRegistry::new();
        let meta = crate::rule::RuleMetadata::new(
            "SS-001",
            "Rule",
            "fixture rule",
            crate::category::Category::Authorization,
            Severity::High,
            crate::confidence::Confidence::High,
            "fix it",
        );
        registry
            .register(Box::new(FixedLineRule { meta, line: 2 }))
            .unwrap();
        let outcome = engine::scan_source_str(src, "src/lib.rs", &ScanConfig::default(), &registry);
        let value: serde_json::Value =
            serde_json::from_str(&render_json(&outcome).unwrap()).unwrap();
        assert_eq!(value["stats"]["findings_suppressed"], 0);
        assert_eq!(value["suppressions"][0]["applied"], false);
        assert_eq!(value["findings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn sarif_report_marks_suppressions() {
        let (outcome, registry) = suppressed_sample();
        let text = render_sarif(&outcome, &registry);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let results = value["runs"][0]["results"].as_array().unwrap();
        assert_eq!(
            results.len(),
            1,
            "suppressed results stay in the SARIF report"
        );
        assert_eq!(results[0]["ruleId"], "SS-001");
        assert_eq!(results[0]["suppressions"][0]["kind"], "inSource");
        assert_eq!(results[0]["suppressions"][0]["status"], "accepted");
        assert_eq!(
            results[0]["suppressions"][0]["justification"],
            "reviewed by the security team"
        );
        assert_eq!(results[0]["properties"]["suppressed"], true);
        assert_eq!(results[0]["properties"]["suppressedBy"], "src/lib.rs:1");
    }

    #[test]
    fn markdown_report_lists_suppressed_findings() {
        let (outcome, _) = suppressed_sample();
        let text = render_markdown(&outcome);
        assert!(text.contains("## Suppressed findings"));
        assert!(text.contains("reviewed by the security team"));
    }

    fn config_suppressed_sample() -> (ScanOutcome, RuleRegistry) {
        let src = "fn a() {}\n";
        let mut registry = RuleRegistry::new();
        let meta = crate::rule::RuleMetadata::new(
            "SS-001",
            "Configured rule",
            "fixture rule",
            crate::category::Category::Authorization,
            Severity::High,
            crate::confidence::Confidence::High,
            "fix it",
        );
        registry
            .register(Box::new(FixedLineRule { meta, line: 1 }))
            .unwrap();
        let config = ScanConfig {
            suppressions: vec![crate::config::SuppressionRule {
                path: "src/**".to_string(),
                rule: "SS-001".to_string(),
                reason: Some("accepted by configuration".to_string()),
            }],
            ..ScanConfig::default()
        };
        let outcome = engine::scan_source_str(src, "src/lib.rs", &config, &registry);
        (outcome, registry)
    }

    #[test]
    fn json_report_exposes_configured_suppressions_and_counts() {
        let (outcome, _) = config_suppressed_sample();
        let value: serde_json::Value =
            serde_json::from_str(&render_json(&outcome).unwrap()).unwrap();

        assert_eq!(value["stats"]["config_suppressions_detected"], 1);
        assert_eq!(value["stats"]["config_suppressions_matched"], 1);
        assert_eq!(value["stats"]["config_suppressions_applied"], 1);
        assert_eq!(value["stats"]["findings_suppressed_by_config"], 1);
        assert_eq!(value["config_suppressions"][0]["path"], "src/**");
        assert_eq!(value["config_suppressions"][0]["rule"], "SS-001");
        assert_eq!(value["config_suppressions"][0]["matched"], 1);
        assert_eq!(value["config_suppressions"][0]["applied"], true);
        assert_eq!(value["suppressed"][0]["suppression"]["source"], "config");
        assert_eq!(value["suppressed"][0]["suppression"]["path"], "src/**");
    }

    #[test]
    fn sarif_marks_configured_suppressions_as_external() {
        let (outcome, registry) = config_suppressed_sample();
        let value: serde_json::Value =
            serde_json::from_str(&render_sarif(&outcome, &registry)).unwrap();
        let result = &value["runs"][0]["results"][0];
        assert_eq!(result["suppressions"][0]["kind"], "external");
        assert_eq!(result["properties"]["suppressedBy"], "config:src/**");
        assert_eq!(result["properties"]["suppressionSource"], "config");
    }

    #[test]
    fn terminal_and_markdown_report_configured_suppressions() {
        let (outcome, _) = config_suppressed_sample();
        let terminal = render_terminal(&outcome);
        assert!(terminal.contains(
            "Generated: 0 marked, 0 excluded  Config suppressions: 1 detected, 1 applied"
        ));
        assert!(terminal.contains("configuration path `src/**`"));
        assert!(terminal.contains("accepted by configuration"));

        let markdown = render_markdown(&outcome);
        assert!(markdown.contains("### Configured suppressions"));
        assert!(markdown.contains("| `src/**` | SS-001 | 1 | 1 | true |"));
    }

    #[test]
    fn terminal_color_is_opt_in() {
        let (outcome, _) = sample();
        assert!(!render_terminal(&outcome).contains('\u{1b}'));
        assert!(!render_terminal_compact(&outcome).contains('\u{1b}'));

        let colored = render_terminal_with_color(&outcome, TerminalColor::new(true));
        assert!(colored.contains('\u{1b}'), "expected ANSI escapes");
        assert!(colored.contains("\u{1b}[31m"), "high should be red");

        let colored = render_terminal_compact_with_color(&outcome, TerminalColor::new(true));
        assert!(colored.contains('\u{1b}'));
    }

    #[test]
    fn truncation_is_explicit_in_every_format() {
        let (mut outcome, registry) = sample();
        let total = outcome.findings.len();
        assert!(total > 1, "fixture needs multiple findings, got {total}");
        outcome.truncate_findings(Some(1));

        let terminal = render_terminal(&outcome);
        assert!(terminal.contains(&format!("{} more finding(s) not shown", total - 1)));

        let compact = render_terminal_compact(&outcome);
        assert!(compact.contains(&format!("{} more finding(s) not shown", total - 1)));

        let value: serde_json::Value =
            serde_json::from_str(&render_json(&outcome).unwrap()).unwrap();
        assert_eq!(value["findings"].as_array().unwrap().len(), 1);
        assert_eq!(value["truncation"]["shown"], 1);
        assert_eq!(value["truncation"]["total"], total);
        assert_eq!(value["truncation"]["omitted"], total - 1);

        let markdown = render_markdown(&outcome);
        assert!(markdown.contains(&format!("{} more finding(s)", total - 1)));

        let html = render_html(&outcome);
        assert!(html.contains(&format!("{} more finding(s)", total - 1)));

        let github = render_github(&outcome);
        assert!(github.contains("::notice::"));
        assert!(github.contains(&format!("{} more finding(s)", total - 1)));

        let sarif: serde_json::Value =
            serde_json::from_str(&render_sarif(&outcome, &registry)).unwrap();
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 1);
        assert_eq!(
            sarif["runs"][0]["properties"]["truncation"]["omitted"],
            total - 1
        );
        assert!(
            sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]["message"]["text"]
                .as_str()
                .unwrap()
                .contains(&format!("{} more finding(s)", total - 1))
        );
    }

    #[test]
    fn machine_formats_never_contain_ansi_escapes() {
        let (outcome, registry) = sample();
        assert!(!render_json(&outcome).unwrap().contains('\u{1b}'));
        assert!(!render_sarif(&outcome, &registry).contains('\u{1b}'));
        assert!(!render_markdown(&outcome).contains('\u{1b}'));
        assert!(!render_html(&outcome).contains('\u{1b}'));
        assert!(!render_github(&outcome).contains('\u{1b}'));
    }

    fn malicious_outcome() -> ScanOutcome {
        let (mut outcome, _) = sample();
        let meta = crate::rule::RuleMetadata::new(
            "SS-001",
            "Title",
            "fixture rule",
            crate::category::Category::Authorization,
            Severity::High,
            crate::confidence::Confidence::High,
            "fix it",
        );
        let mut finding = Finding::new(
            &meta,
            crate::finding::SourceLocation::new(
                "src/a,b:c\n::error file=evil.rs,line=1::owned.rs",
                42,
            ),
            "100% bad\r\n::error file=evil.rs,line=1::injected",
        );
        finding.title = "title, with: separators\n::warning::injected".to_string();
        outcome.findings = vec![finding];
        outcome
    }

    #[test]
    fn github_annotations_escape_paths_titles_and_evidence() {
        let outcome = malicious_outcome();
        let text = render_github(&outcome);
        assert_eq!(
            text.lines().count(),
            1,
            "one finding must produce exactly one annotation line"
        );
        assert!(text.starts_with("::error "));
        assert!(text.contains("%0A"), "newlines must be escaped");
        assert!(text.contains("%0D"), "carriage returns must be escaped");
        assert!(text.contains("%25"), "percent signs must be escaped");
        assert!(text.contains("%3A"), "colons must be escaped in properties");
        assert!(text.contains("%2C"), "commas must be escaped in properties");
        assert!(
            !text.contains("\n::error file=evil"),
            "crafted input must not start a new workflow command"
        );
        assert!(
            !text.contains("\r"),
            "no raw carriage returns may reach the workflow command"
        );
    }

    #[test]
    fn github_annotation_levels_match_severity() {
        let (mut outcome, _) = sample();
        let severities = [
            (Severity::Critical, "::error "),
            (Severity::High, "::error "),
            (Severity::Medium, "::warning "),
            (Severity::Low, "::notice "),
            (Severity::Info, "::notice "),
        ];
        let mut expected = Vec::new();
        for (severity, prefix) in severities {
            outcome.findings[0].severity = severity;
            let text = render_github(&outcome);
            assert!(text.starts_with(prefix), "got: {text}");
            expected.push(prefix);
        }
        assert_eq!(expected.len(), 5);
    }

    #[test]
    fn github_annotations_survive_fuzzed_source_text() {
        // Deterministic, dependency-free fuzz loop. The alphabet is chosen to
        // hit workflow separators, escape characters, and shell metacharacters.
        const ALPHABET: &[char] = &[
            '%', ':', ',', '\r', '\n', '$', '(', ')', '`', '"', '\'', '\\', ';', '&', '|', '{',
            '}', '[', ']', '=', ' ', 'a', 'Z', '0',
        ];
        let (mut outcome, _) = sample();
        let mut seed = 0x5eed_1234_u64;
        for _ in 0..256 {
            let mut next = || {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                ALPHABET[((seed >> 33) as usize) % ALPHABET.len()]
            };
            let path: String = (0..24).map(|_| next()).collect();
            let title: String = (0..24).map(|_| next()).collect();
            let evidence: String = (0..48).map(|_| next()).collect();
            let mut finding = outcome.findings[0].clone();
            finding.location.file = std::path::PathBuf::from(format!("src/{path}.rs"));
            finding.title = title;
            finding.evidence = evidence;
            outcome.findings = vec![finding];

            let text = render_github(&outcome);
            assert_eq!(text.lines().count(), 1, "got: {text:?}");
            assert!(text.starts_with("::error "), "got: {text:?}");
            assert!(!text.contains('\r'), "got: {text:?}");
            assert_eq!(
                text.matches('\n').count(),
                1,
                "annotations must be a single line: {text:?}"
            );
            // Every literal percent must start a valid workflow escape.
            let bytes = text.as_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                if *byte == b'%' {
                    let rest = &text[index + 1..];
                    assert!(
                        rest.starts_with("25")
                            || rest.starts_with("0A")
                            || rest.starts_with("0D")
                            || rest.starts_with("3A")
                            || rest.starts_with("2C"),
                        "unescaped percent in: {text:?}"
                    );
                }
            }
        }
    }
}
