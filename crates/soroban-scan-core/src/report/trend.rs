//! Multi-scan trend dashboard.
//!
//! Aggregates the summary fields of several JSON scan reports into one static,
//! self-contained HTML page. Only counts and project labels are rendered:
//! finding titles, evidence, and source text are never included.

use serde_json::Value;

/// Maximum number of reports accepted by one dashboard.
pub const MAX_REPORTS: usize = 50;

/// Maximum accepted size of one JSON report, in bytes.
pub const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum number of findings accepted from one report.
pub const MAX_FINDINGS: usize = 100_000;

/// A malformed or oversized trend input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrendError {
    /// More reports were supplied than [`MAX_REPORTS`].
    TooManyReports(usize),
    /// One report exceeds [`MAX_REPORT_BYTES`].
    TooLarge {
        /// Input label.
        label: String,
        /// Observed size in bytes.
        bytes: usize,
    },
    /// One report is not a usable JSON scan report.
    Invalid {
        /// Input label.
        label: String,
        /// Human-readable reason.
        message: String,
    },
}

impl std::fmt::Display for TrendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrendError::TooManyReports(count) => f.write_str(&format!(
                "too many reports ({count}; limit {MAX_REPORTS} per dashboard)"
            )),
            TrendError::TooLarge { label, bytes } => f.write_str(&format!(
                "{label}: report is too large ({bytes} bytes; limit {MAX_REPORT_BYTES} bytes)"
            )),
            TrendError::Invalid { label, message } => {
                f.write_str(&format!("{label}: invalid report: {message}"))
            }
        }
    }
}

impl std::error::Error for TrendError {}

/// The summary of one scan run.
///
/// Every field except `label` is optional so a partially written or older
/// report still contributes the data it does have. Missing values render as
/// `—` instead of failing the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrendRun {
    /// Stable input label, usually the report file name.
    pub label: String,
    /// Project root recorded by the scan.
    pub project: Option<String>,
    /// Files analyzed.
    pub files_analyzed: Option<usize>,
    /// Number of findings.
    pub findings: Option<usize>,
    /// Finding counts for critical, high, medium, low, and info.
    pub severity: [Option<usize>; 5],
}

/// Parses one JSON scan report into a trend point.
pub fn parse_run(label: impl Into<String>, text: &str) -> Result<TrendRun, TrendError> {
    let label = label.into();
    if text.len() > MAX_REPORT_BYTES {
        return Err(TrendError::TooLarge {
            label,
            bytes: text.len(),
        });
    }
    if text.trim().is_empty() {
        return Err(TrendError::Invalid {
            label,
            message: "document is empty".to_string(),
        });
    }
    let value: Value = serde_json::from_str(text).map_err(|error| TrendError::Invalid {
        label: label.clone(),
        message: error.to_string(),
    })?;

    let project = value
        .get("project")
        .and_then(|project| project.get("root"))
        .and_then(Value::as_str)
        .map(str::to_string);

    let files_analyzed = value
        .get("stats")
        .and_then(|stats| stats.get("files_analyzed"))
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok());

    let mut severity: [Option<usize>; 5] = [None; 5];
    let findings = match value.get("findings") {
        None => None,
        Some(findings) => {
            let findings = findings.as_array().ok_or_else(|| TrendError::Invalid {
                label: label.clone(),
                message: "findings is not an array".to_string(),
            })?;
            if findings.len() > MAX_FINDINGS {
                return Err(TrendError::Invalid {
                    label,
                    message: format!(
                        "too many findings ({}; limit {MAX_FINDINGS})",
                        findings.len()
                    ),
                });
            }
            let mut counts = [0usize; 5];
            let mut known = [true; 5];
            for finding in findings {
                match finding.get("severity").and_then(Value::as_str) {
                    Some("critical") => counts[4] += 1,
                    Some("high") => counts[3] += 1,
                    Some("medium") => counts[2] += 1,
                    Some("low") => counts[1] += 1,
                    Some("info") => counts[0] += 1,
                    _ => {
                        // An unknown severity makes the per-severity split
                        // unreliable, but the total is still known.
                        known.fill(false);
                    }
                }
            }
            for (index, count) in counts.into_iter().enumerate() {
                severity[index] = known[index].then_some(count);
            }
            Some(findings.len())
        }
    };

    Ok(TrendRun {
        label,
        project,
        files_analyzed,
        findings,
        severity,
    })
}

fn optional(value: Option<usize>) -> String {
    value.map_or_else(|| "—".to_string(), |value| value.to_string())
}

fn width(count: Option<usize>, max: usize) -> f64 {
    match count {
        Some(0) | None => 0.0,
        Some(count) => 120.0 * count as f64 / max.max(1) as f64,
    }
}

/// Renders a static, self-contained dashboard from several runs.
///
/// The page uses inline CSS and inline SVG only. It contains no JavaScript,
/// no remote assets, and no source text.
pub fn render_dashboard(title: &str, runs: &[TrendRun]) -> String {
    use super::escape_html;

    let known: Vec<usize> = runs.iter().filter_map(|run| run.findings).collect();
    let latest = runs.iter().rev().find_map(|run| run.findings);
    let change = match (known.first(), known.last()) {
        (Some(first), Some(last)) if known.len() > 1 => Some(*last as i64 - *first as i64),
        _ => None,
    };
    let max_findings = known.iter().copied().max().unwrap_or(0);
    let plot_width = 640.0;
    let plot_height = 160.0;
    let slot = if runs.is_empty() {
        plot_width
    } else {
        plot_width / runs.len() as f64
    };

    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str(&format!("<title>{}</title>\n", escape_html(title)));
    out.push_str("<style>");
    out.push_str(
        ":root{color-scheme:light dark;--bg:#f7f8fa;--panel:#fff;--ink:#1c2430;--muted:#5b6776;\
         --line:#d8dee7;--bar:#2f6f9f}*{box-sizing:border-box}body{margin:0;background:var(--bg);\
         color:var(--ink);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}\
         main{max-width:1040px;margin:0 auto;padding:2rem 1.25rem 4rem}h1{font-size:1.65rem;margin:0 0 .35rem}\
         h2{font-size:1.15rem;margin:2rem 0 .6rem;border-bottom:1px solid var(--line);padding-bottom:.35rem}\
         .meta{color:var(--muted);margin:.2rem 0}.cards{display:grid;gap:.6rem;\
         grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin:1rem 0}\
         .card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:.7rem .8rem}\
         .card .label{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}\
         .card .value{font-size:1.35rem;font-weight:650}\
         table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);\
         border-radius:8px;overflow:hidden}th,td{text-align:left;padding:.5rem .65rem;\
         border-bottom:1px solid var(--line);vertical-align:top}tr:last-child td{border-bottom:0}\
         th{font-size:.8rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}\
         svg{width:100%;height:auto;background:var(--panel);border:1px solid var(--line);border-radius:8px}\
         .bar{fill:var(--bar)}.axis{stroke:var(--line);stroke-width:1}.missing{fill:var(--muted);font-size:12px}\
         .note{color:var(--muted);font-style:italic}@media (prefers-color-scheme:dark){:root{--bg:#12161c;\
         --panel:#1a2028;--ink:#e6eaf0;--muted:#a3adba;--line:#2c3541;--bar:#6fa8d6}}\
         @media print{@page{margin:18mm}:root{color-scheme:light;--bg:#fff;--panel:#fff;--ink:#000;\
         --muted:#333;--line:#999}body{background:#fff;color:#000}.card,.bar,table{break-inside:avoid}}",
    );
    out.push_str("</style>\n</head>\n<body>\n<main>\n");
    out.push_str(&format!("<h1>{}</h1>\n", escape_html(title)));
    out.push_str(
        "<p class=\"meta\">Aggregated from JSON scan reports. Counts only: \
         finding text and source are never included.</p>\n",
    );

    out.push_str("<div class=\"cards\">\n");
    out.push_str(&format!(
        "<div class=\"card\"><div class=\"label\">Runs</div><div class=\"value\">{}</div></div>\n",
        runs.len()
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div class=\"label\">Latest findings</div><div class=\"value\">{}</div></div>\n",
        optional(latest)
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div class=\"label\">Change</div><div class=\"value\">{}</div></div>\n",
        match change {
            Some(0) => "0".to_string(),
            Some(value) if value > 0 => format!("+{value}"),
            Some(value) => value.to_string(),
            None => "—".to_string(),
        }
    ));
    out.push_str(&format!(
        "<div class=\"card\"><div class=\"label\">Runs with data</div><div class=\"value\">{}</div></div>\n",
        known.len()
    ));
    out.push_str("</div>\n");

    out.push_str("<h2>Findings over time</h2>\n");
    out.push_str(&format!(
        "<svg role=\"img\" aria-label=\"Findings per run\" viewBox=\"0 0 {plot_width} {plot_height}\" \
         xmlns=\"http://www.w3.org/2000/svg\">\n"
    ));
    out.push_str(&format!(
        "<line class=\"axis\" x1=\"0\" y1=\"140\" x2=\"{plot_width}\" y2=\"140\"/>\n"
    ));
    for (index, run) in runs.iter().enumerate() {
        let x = index as f64 * slot + slot / 2.0;
        match run.findings {
            Some(count) => {
                let bar_width = (slot * 0.5).min(40.0);
                let height = width(Some(count), max_findings);
                out.push_str(&format!(
                    "<rect class=\"bar\" x=\"{:.1}\" y=\"{:.1}\" width=\"{bar_width:.1}\" height=\"{height:.1}\">\
                     <title>{}</title></rect>\n",
                    x - bar_width / 2.0,
                    140.0 - height,
                    escape_html(&run.label)
                ));
            }
            None => out.push_str(&format!(
                "<text class=\"missing\" x=\"{x:.1}\" y=\"136\" text-anchor=\"middle\">—</text>\n"
            )),
        }
    }
    out.push_str("</svg>\n");

    out.push_str("<h2>Runs</h2>\n");
    if runs.is_empty() {
        out.push_str("<p class=\"note\">No scan reports were supplied.</p>\n");
    } else {
        out.push_str(
            "<table><thead><tr><th>Run</th><th>Project</th><th>Files</th><th>Findings</th>\
             <th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead><tbody>\n",
        );
        for run in runs {
            out.push_str(&format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td>\
                 <td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                escape_html(&run.label),
                escape_html(run.project.as_deref().unwrap_or("—")),
                optional(run.files_analyzed),
                optional(run.findings),
                optional(run.severity[4]),
                optional(run.severity[3]),
                optional(run.severity[2]),
                optional(run.severity[1]),
                optional(run.severity[0])
            ));
        }
        out.push_str("</tbody></table>\n");
    }
    out.push_str(
        "<p class=\"note\">Missing values are shown as — and are ignored when computing \
         the latest value and change.</p>\n",
    );
    out.push_str("</main>\n</body>\n</html>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(label: &str, findings: Option<usize>, severity: [Option<usize>; 5]) -> TrendRun {
        TrendRun {
            label: label.to_string(),
            project: Some("fixtures/contracts".to_string()),
            files_analyzed: Some(3),
            findings,
            severity,
        }
    }

    #[test]
    fn parses_summary_fields_and_handles_missing_data() {
        let report = r#"{
            "schema_version": "1",
            "project": { "root": "contracts" },
            "stats": { "files_analyzed": 7 },
            "findings": [
                { "severity": "high", "evidence": "SECRET_SOURCE_MARKER" },
                { "severity": "high" },
                { "severity": "low" }
            ]
        }"#;
        let parsed = parse_run("run.json", report).unwrap();
        assert_eq!(parsed.project.as_deref(), Some("contracts"));
        assert_eq!(parsed.files_analyzed, Some(7));
        assert_eq!(parsed.findings, Some(3));
        assert_eq!(
            parsed.severity,
            [Some(0), Some(1), Some(0), Some(2), Some(0)]
        );

        let partial = parse_run("partial.json", r#"{"schema_version":"1"}"#).unwrap();
        assert_eq!(partial.findings, None);
        assert_eq!(partial.files_analyzed, None);
        assert_eq!(partial.severity, [None; 5]);
    }

    #[test]
    fn unknown_severity_keeps_the_total_but_drops_the_split() {
        let parsed = parse_run(
            "run.json",
            r#"{"schema_version":"1","findings":[{"severity":"urgent"}]}"#,
        )
        .unwrap();
        assert_eq!(parsed.findings, Some(1));
        assert_eq!(parsed.severity, [None; 5]);
    }

    #[test]
    fn dashboard_renders_multiple_runs_and_missing_values() {
        let runs = vec![
            run(
                "one.json",
                Some(5),
                [Some(0), Some(1), Some(2), Some(2), Some(0)],
            ),
            run("two.json", None, [None; 5]),
        ];
        let html = render_dashboard("Trend", &runs);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("<table>"));
        assert!(html.contains("one.json"));
        assert!(html.contains("two.json"));
        assert!(html.contains("—"));
        assert!(!html.contains("<script"));
        assert!(!html.contains("<link"));
        assert!(!html.contains("src="));
    }

    #[test]
    fn dashboard_never_includes_source_text() {
        let parsed = parse_run(
            "run.json",
            r#"{"schema_version":"1","findings":[{"severity":"high","evidence":"SECRET_SOURCE_MARKER","title":"SECRET_TITLE"}]}"#,
        )
        .unwrap();
        let html = render_dashboard("Trend", &[parsed]);
        assert!(!html.contains("SECRET_SOURCE_MARKER"));
        assert!(!html.contains("SECRET_TITLE"));
    }

    #[test]
    fn bounds_are_enforced() {
        assert!(matches!(
            parse_run("run.json", ""),
            Err(TrendError::Invalid { .. })
        ));
        let huge = " ".repeat(MAX_REPORT_BYTES + 1);
        assert!(matches!(
            parse_run("run.json", &huge),
            Err(TrendError::TooLarge { .. })
        ));
    }
}
