//! Reporting: terminal, JSON, SARIF, and Markdown renderers.
//!
//! Machine-readable formats are stable and versioned by the tool version. No
//! renderer ever emits environment variables, absolute user paths, or secrets.

use serde::Serialize;

use crate::config::ScanConfig;
use crate::engine::{FindingTruncation, ScanOutcome, SuppressedFinding, SuppressionInfo};
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
    /// GitHub Actions workflow annotations (`::error`, `::warning`, `::notice`).
    Github,
}

impl OutputFormat {
    /// Parses a format name.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "terminal" | "text" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            "github" => Ok(OutputFormat::Github),
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
            OutputFormat::Github => "github",
        }
    }
}

/// Renders a scan outcome in the requested format.
pub fn render(outcome: &ScanOutcome, registry: &RuleRegistry, format: OutputFormat) -> String {
    match format {
        OutputFormat::Terminal => render_terminal(outcome),
        OutputFormat::Json => render_json(outcome)
            .unwrap_or_else(|e| format!("{{\"error\":\"failed to serialize report: {e}\"}}")),
        OutputFormat::Sarif => render_sarif(outcome, registry),
        OutputFormat::Markdown => render_markdown(outcome),
        OutputFormat::Github => render_github(outcome),
    }
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
        "Files: {}  Rules run: {}  Skipped: {}  Suppressions: {}\n\n",
        outcome.stats.files_analyzed,
        outcome.stats.rules_run,
        outcome.stats.rules_skipped,
        outcome.stats.suppressions_detected
    ));

    if outcome.findings.is_empty() {
        if outcome.truncation.is_none() {
            out.push_str("No security findings.\n");
        }
    } else {
        for finding in &outcome.findings {
            let label = format!("{:<8}", finding.severity.as_str().to_ascii_uppercase());
            out.push_str(&format!(
                "{} {:<7} {}\n",
                color.severity(finding.severity, &label),
                finding.rule_id,
                finding.location.display_label()
            ));
            out.push_str(&format!("         {}\n", finding.title));
            out.push_str(&format!("         confidence: {}\n", finding.confidence));
            out.push_str(&format!("         evidence: {}\n", finding.evidence));
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
            out.push_str(&format!(
                "           suppressed by {}:{} (`ignore {}`)\n",
                display_suppression_file(&suppressed.suppression.file),
                suppressed.suppression.line,
                suppressed.suppression.rules
            ));
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
    findings: &'a [Finding],
    suppressed: &'a [SuppressedFinding],
    suppressions: Vec<SuppressionJson>,
    diagnostics: &'a [Diagnostic],
    /// Present only when the caller bounded the number of reported findings.
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation: Option<FindingTruncation>,
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
    rules_run: usize,
    rules_skipped: usize,
    findings_raw: usize,
    findings_rejected: usize,
    suppressions_detected: usize,
    findings_suppressed: usize,
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
            rules_run: outcome.stats.rules_run,
            rules_skipped: outcome.stats.rules_skipped,
            findings_raw: outcome.stats.findings_raw,
            findings_rejected: outcome.stats.findings_rejected,
            suppressions_detected: outcome.stats.suppressions_detected,
            findings_suppressed: outcome.stats.findings_suppressed,
        },
        effective_config: &outcome.config,
        findings: &outcome.findings,
        suppressed: &outcome.suppressed,
        suppressions: suppression_reports(outcome),
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
fn sarif_result(finding: &Finding, suppression: Option<&SuppressionInfo>) -> serde_json::Value {
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

    if let Some(suppression) = suppression {
        let justification = suppression
            .reason
            .clone()
            .unwrap_or_else(|| "inline soroban-scan suppression".to_string());
        result["suppressions"] = json!([{
            "kind": "inSource",
            "status": "accepted",
            "justification": justification,
        }]);
        result["properties"]["suppressed"] = json!(true);
        result["properties"]["suppressedBy"] =
            json!(format!("{}:{}", suppression.file, suppression.line));
        result["properties"]["suppressedRules"] = json!(suppression.rules);
    }

    result
}

/// Renders the SARIF 2.1.0 report.
pub fn render_sarif(outcome: &ScanOutcome, registry: &RuleRegistry) -> String {
    use serde_json::{json, Value};

    let rules: Vec<Value> = registry
        .metadata_sorted()
        .iter()
        .map(|meta| {
            json!({
                "id": meta.id,
                "name": meta.title,
                "shortDescription": { "text": meta.title },
                "fullDescription": { "text": meta.description },
                "helpUri": meta.references.first().copied().unwrap_or(TOOL_URL),
                "defaultConfiguration": { "level": sarif_level(meta.default_severity) },
                "properties": {
                    "category": meta.category.as_str(),
                    "confidence": meta.default_confidence.as_str(),
                    "severity": meta.default_severity.as_str()
                }
            })
        })
        .collect();

    let mut results: Vec<Value> = outcome
        .findings
        .iter()
        .map(|finding| sarif_result(finding, None))
        .collect();

    // Suppressed findings are never dropped: they stay in the SARIF results and
    // are marked as in-source suppressions (SARIF 2.1.0 `suppressions`).
    results.extend(
        outcome
            .suppressed
            .iter()
            .map(|suppressed| sarif_result(&suppressed.finding, Some(&suppressed.suppression))),
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

    if let Some(truncation) = outcome.truncation {
        run["properties"] = json!({ "truncation": truncation });
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
        "- **Suppressed (excluded from the gate):** {}\n\n",
        outcome.stats.findings_suppressed
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
        out.push_str(&format!(
            "- **{}** `{}` at `{}` — suppressed by `{}:{}` (`ignore {}`)\n",
            suppressed.finding.rule_id,
            suppressed.finding.title,
            suppressed.finding.location.display_label(),
            display_suppression_file(&suppressed.suppression.file),
            suppressed.suppression.line,
            suppressed.suppression.rules
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
    }

    #[test]
    fn markdown_report_contains_table() {
        let (outcome, _) = sample();
        let text = render_markdown(&outcome);
        assert!(text.contains("| Severity | Count |"));
        assert!(text.contains("SS-001"));
    }

    #[test]
    fn output_format_parsing() {
        assert_eq!(OutputFormat::parse("SARIF").unwrap(), OutputFormat::Sarif);
        assert_eq!(OutputFormat::parse("md").unwrap(), OutputFormat::Markdown);
        assert_eq!(OutputFormat::parse("github").unwrap(), OutputFormat::Github);
        assert_eq!(OutputFormat::Github.as_str(), "github");
        assert!(OutputFormat::parse("xml").is_err());
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
