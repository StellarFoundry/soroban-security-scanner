//! Policy-driven pull request status gate (#341).
//!
//! The scanner's exit code already reflects the configured fail policy, but a
//! pull request needs one named status that says *why*. This module turns the
//! effective policy and the findings the gate considered into a small,
//! deterministic record: a conclusion (`success`, `failure` or `neutral`), a
//! one-line title, and a concise Markdown summary that links to the full
//! report. CI publishes the record as a check run; nothing here performs
//! network access.
//!
//! The gate mirrors the CLI exit gate exactly:
//!
//! - Only findings the gate sees are counted. Findings removed by inline
//!   directives, configured suppressions or unexpired waivers never reach it,
//!   and with a baseline only *new* findings are considered, so suppressed and
//!   baseline findings can never fail the status.
//! - An expired waiver fails the gate unless the policy disables it.
//! - `fail_on = "none"` disables the gate and yields `neutral`, as does a scan
//!   that analyzed no files (for example a path filter that matched nothing).

use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// Schema version of the serialized [`StatusGate`] record.
pub const STATUS_GATE_SCHEMA_VERSION: u32 = 1;

/// Longest report URL accepted for the summary link.
pub const MAX_REPORT_URL_LEN: usize = 2048;

/// Outcome of the status gate, using the GitHub Checks API vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateConclusion {
    /// The policy is enforced and nothing violates it.
    Success,
    /// At least one gated finding or expired waiver violates the policy.
    Failure,
    /// The gate is disabled or there was nothing to evaluate.
    Neutral,
}

impl GateConclusion {
    /// Stable lowercase name, as used by the Checks API.
    pub fn as_str(self) -> &'static str {
        match self {
            GateConclusion::Success => "success",
            GateConclusion::Failure => "failure",
            GateConclusion::Neutral => "neutral",
        }
    }
}

/// Everything the gate needs, already reduced to what the exit gate saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GateInput {
    /// Effective fail threshold; `None` means the gate is disabled.
    pub threshold: Option<Severity>,
    /// Severities of the findings the gate considers: every unsuppressed
    /// finding, or only the new ones when a baseline is supplied.
    pub gated: Vec<Severity>,
    /// Findings accepted by a baseline and therefore not gated.
    pub baseline_accepted: usize,
    /// Findings removed from the gate by suppressions or unexpired waivers.
    pub suppressed: usize,
    /// Configured waivers that have expired.
    pub expired_waivers: usize,
    /// Files the scan analyzed.
    pub files_analyzed: usize,
    /// Optional link to the full report artifact. Validate it with
    /// [`validate_report_url`] first.
    pub report_url: Option<String>,
}

/// Serializable status-gate record, suitable for a Checks API request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusGate {
    /// Record schema version; currently `1`.
    pub schema_version: u32,
    /// Gate conclusion.
    pub conclusion: GateConclusion,
    /// One-line title for the check.
    pub title: String,
    /// Concise Markdown summary for the check.
    pub summary: String,
    /// Effective threshold: `none` or a severity name.
    pub threshold: String,
    /// Findings the gate considered.
    pub gated: usize,
    /// Gated findings at or above the threshold.
    pub blocking: usize,
    /// Findings excluded by suppressions or waivers.
    pub suppressed: usize,
    /// Findings accepted by a baseline.
    pub baseline_accepted: usize,
    /// Expired waivers.
    pub expired_waivers: usize,
    /// Link to the full report artifact, when one was supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_url: Option<String>,
}

/// Checks that `url` is a bounded `http(s)` URL that is safe to embed in a
/// Markdown link.
///
/// Credentials in the URL are rejected so a secret can never be published in
/// a check summary.
pub fn validate_report_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Err("report URL must not be empty".to_string());
    }
    if url.len() > MAX_REPORT_URL_LEN {
        return Err(format!(
            "report URL is longer than {MAX_REPORT_URL_LEN} characters"
        ));
    }
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest
    } else {
        return Err("report URL must start with https:// or http://".to_string());
    };
    if let Some(bad) = url
        .chars()
        .find(|c| c.is_whitespace() || c.is_control() || "()<>\"'`[]\\".contains(*c))
    {
        return Err(format!(
            "report URL contains a disallowed character {bad:?}"
        ));
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err("report URL has no host".to_string());
    }
    if authority.contains('@') {
        return Err("report URL must not contain credentials".to_string());
    }
    Ok(())
}

/// Evaluates the gate.
pub fn evaluate(input: &GateInput) -> StatusGate {
    let blocking = match input.threshold {
        Some(threshold) => input
            .gated
            .iter()
            .filter(|severity| severity.meets(threshold))
            .count(),
        None => 0,
    };
    let expired = input.expired_waivers;
    let conclusion = match input.threshold {
        Some(_) if blocking > 0 || expired > 0 => GateConclusion::Failure,
        None => GateConclusion::Neutral,
        Some(_) if input.files_analyzed == 0 => GateConclusion::Neutral,
        Some(_) => GateConclusion::Success,
    };
    let threshold = input
        .threshold
        .map_or_else(|| "none".to_string(), |severity| severity.to_string());

    let title = match (conclusion, input.threshold) {
        (GateConclusion::Failure, _) => {
            let mut parts = Vec::new();
            if blocking > 0 {
                parts.push(format!("{blocking} finding(s) at or above `{threshold}`"));
            }
            if expired > 0 {
                parts.push(format!("{expired} expired waiver(s)"));
            }
            format!("Policy gate failed: {}", parts.join(", "))
        }
        (GateConclusion::Success, _) => {
            format!("Policy gate passed: no findings at or above `{threshold}`")
        }
        (GateConclusion::Neutral, None) => "Policy gate disabled: fail_on is `none`".to_string(),
        (GateConclusion::Neutral, Some(_)) => {
            "Policy gate neutral: no files were scanned".to_string()
        }
    };

    let mut summary = vec![
        format!("**{title}**"),
        String::new(),
        "| Policy input | Value |".to_string(),
        "| ------------ | ----- |".to_string(),
        format!("| Fail threshold | `{threshold}` |"),
        format!("| Files analyzed | {} |", input.files_analyzed),
        format!("| Gated findings | {} |", input.gated.len()),
        format!("| Blocking findings | {blocking} |"),
        format!(
            "| Suppressed or waived (not gated) | {} |",
            input.suppressed
        ),
        format!(
            "| Accepted by baseline (not gated) | {} |",
            input.baseline_accepted
        ),
        format!("| Expired waivers | {expired} |"),
        String::new(),
    ];
    match &input.report_url {
        Some(url) => summary.push(format!("[Full scan report]({url})")),
        None => summary.push("The full report is attached to the workflow run.".to_string()),
    }

    StatusGate {
        schema_version: STATUS_GATE_SCHEMA_VERSION,
        conclusion,
        title,
        summary: summary.join("\n"),
        threshold,
        gated: input.gated.len(),
        blocking,
        suppressed: input.suppressed,
        baseline_accepted: input.baseline_accepted,
        expired_waivers: expired,
        report_url: input.report_url.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(threshold: Option<Severity>, gated: &[Severity]) -> GateInput {
        GateInput {
            threshold,
            gated: gated.to_vec(),
            files_analyzed: 3,
            ..GateInput::default()
        }
    }

    #[test]
    fn passes_when_no_gated_finding_meets_the_threshold() {
        let gate = evaluate(&input(
            Some(Severity::High),
            &[Severity::Medium, Severity::Low],
        ));
        assert_eq!(gate.conclusion, GateConclusion::Success);
        assert_eq!(gate.blocking, 0);
        assert_eq!(gate.gated, 2);
        assert!(
            gate.title.starts_with("Policy gate passed"),
            "{}",
            gate.title
        );
    }

    #[test]
    fn fails_when_a_gated_finding_meets_the_threshold() {
        let gate = evaluate(&input(
            Some(Severity::High),
            &[Severity::Critical, Severity::High, Severity::Low],
        ));
        assert_eq!(gate.conclusion, GateConclusion::Failure);
        assert_eq!(gate.blocking, 2);
        assert!(gate.title.contains("2 finding(s) at or above `high`"));
    }

    #[test]
    fn disabled_policy_is_neutral_even_with_findings() {
        let mut gate_input = input(None, &[Severity::Critical]);
        gate_input.expired_waivers = 1;
        let gate = evaluate(&gate_input);
        assert_eq!(gate.conclusion, GateConclusion::Neutral);
        assert_eq!(gate.threshold, "none");
        assert_eq!(gate.blocking, 0);
    }

    #[test]
    fn empty_scan_is_neutral() {
        let mut gate_input = input(Some(Severity::High), &[]);
        gate_input.files_analyzed = 0;
        let gate = evaluate(&gate_input);
        assert_eq!(gate.conclusion, GateConclusion::Neutral);
        assert!(gate.title.contains("no files were scanned"));
    }

    #[test]
    fn suppressed_and_baseline_findings_never_fail_the_gate() {
        let mut gate_input = input(Some(Severity::Low), &[]);
        gate_input.suppressed = 4;
        gate_input.baseline_accepted = 7;
        let gate = evaluate(&gate_input);
        assert_eq!(gate.conclusion, GateConclusion::Success);
        assert!(gate
            .summary
            .contains("| Suppressed or waived (not gated) | 4 |"));
        assert!(gate
            .summary
            .contains("| Accepted by baseline (not gated) | 7 |"));
    }

    #[test]
    fn expired_waiver_fails_an_enforced_gate() {
        let mut gate_input = input(Some(Severity::Critical), &[Severity::Low]);
        gate_input.expired_waivers = 1;
        let gate = evaluate(&gate_input);
        assert_eq!(gate.conclusion, GateConclusion::Failure);
        assert_eq!(gate.blocking, 0);
        assert!(gate.title.contains("1 expired waiver(s)"));
    }

    #[test]
    fn summary_links_to_the_report_artifact() {
        let url = "https://github.com/o/r/actions/runs/1/artifacts/2";
        let mut gate_input = input(Some(Severity::High), &[]);
        gate_input.report_url = Some(url.to_string());
        let gate = evaluate(&gate_input);
        assert!(gate.summary.contains(&format!("[Full scan report]({url})")));
        assert_eq!(gate.report_url.as_deref(), Some(url));

        let gate = evaluate(&input(Some(Severity::High), &[]));
        assert!(!gate.summary.contains("]("));
        assert_eq!(gate.report_url, None);
    }

    #[test]
    fn serializes_with_lowercase_conclusion() {
        let gate = evaluate(&input(Some(Severity::High), &[Severity::High]));
        let value = serde_json::to_value(&gate).unwrap();
        assert_eq!(value["conclusion"], "failure");
        assert_eq!(value["schema_version"], STATUS_GATE_SCHEMA_VERSION);
        assert!(value.get("report_url").is_none());
        let back: StatusGate = serde_json::from_value(value).unwrap();
        assert_eq!(back, gate);
    }

    #[test]
    fn report_url_validation() {
        assert!(validate_report_url("https://example.com/report.json").is_ok());
        assert!(validate_report_url("http://ci.local/run/1?x=1#y").is_ok());
        assert!(validate_report_url("").is_err());
        assert!(validate_report_url("ftp://example.com/r").is_err());
        assert!(validate_report_url("javascript:alert(1)").is_err());
        assert!(validate_report_url("https://").is_err());
        assert!(validate_report_url("https://user:token@example.com/r").is_err());
        assert!(validate_report_url("https://example.com/a b").is_err());
        assert!(validate_report_url("https://example.com/a)b").is_err());
        let long = format!("https://example.com/{}", "a".repeat(MAX_REPORT_URL_LEN));
        assert!(validate_report_url(&long).is_err());
    }

    #[test]
    fn conclusion_names_match_the_checks_api() {
        assert_eq!(GateConclusion::Success.as_str(), "success");
        assert_eq!(GateConclusion::Failure.as_str(), "failure");
        assert_eq!(GateConclusion::Neutral.as_str(), "neutral");
    }
}
