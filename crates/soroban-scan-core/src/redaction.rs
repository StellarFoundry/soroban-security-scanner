//! Opt-in report redaction.
//!
//! Redaction replaces selected fields with a stable hash at render time. It
//! never changes a finding's rule id, location line, or fingerprint, so
//! baselines, `compare`, and `dashboard` keep working on redacted reports.
//!
//! Redaction is bounded and limited: it only covers the fields listed here. It
//! cannot find arbitrary sensitive content in free-form text, and it never
//! rewrites fingerprints or rule metadata. Callers must not treat it as a
//! guarantee that a report contains no secret.

use sha2::{Digest, Sha256};

use crate::baseline::BaselineReport;
use crate::engine::ScanOutcome;
use crate::finding::Finding;

/// Maximum number of redaction fields accepted per invocation.
pub const MAX_FIELDS: usize = 32;
/// Prefix of every redacted value.
pub const REDACTED_PREFIX: &str = "sha256:";

/// A report field that can be redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionField {
    /// The project root label.
    ProjectRoot,
    /// Finding titles (including suppressed findings and baseline entries).
    FindingTitle,
    /// Finding descriptions.
    FindingDescription,
    /// Finding evidence snippets.
    FindingEvidence,
    /// Finding remediation guidance.
    FindingRemediation,
    /// Finding location file paths.
    FindingLocationFile,
    /// Suppression reasons and suppression audit paths.
    SuppressionReason,
    /// Suppression directive and configured suppression file paths.
    SuppressionFile,
    /// Waiver owner names.
    WaiverOwner,
    /// Waiver reasons.
    WaiverReason,
    /// Diagnostic messages.
    DiagnosticMessage,
    /// Diagnostic file paths.
    DiagnosticPath,
}

impl RedactionField {
    /// Parses one configured field name.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim() {
            "project.root" => Ok(RedactionField::ProjectRoot),
            "finding.title" => Ok(RedactionField::FindingTitle),
            "finding.description" => Ok(RedactionField::FindingDescription),
            "finding.evidence" => Ok(RedactionField::FindingEvidence),
            "finding.remediation" => Ok(RedactionField::FindingRemediation),
            "finding.location.file" => Ok(RedactionField::FindingLocationFile),
            "suppression.reason" => Ok(RedactionField::SuppressionReason),
            "suppression.file" => Ok(RedactionField::SuppressionFile),
            "waiver.owner" => Ok(RedactionField::WaiverOwner),
            "waiver.reason" => Ok(RedactionField::WaiverReason),
            "diagnostic.message" => Ok(RedactionField::DiagnosticMessage),
            "diagnostic.path" => Ok(RedactionField::DiagnosticPath),
            other => Err(format!("unknown redaction field: {other}")),
        }
    }
}

/// Parses and validates a list of redaction field names.
///
/// Duplicates are removed. More than [`MAX_FIELDS`] entries are rejected so a
/// configuration file cannot grow the redaction work without bound.
pub fn validate_fields(fields: &[String]) -> Result<Vec<RedactionField>, String> {
    if fields.len() > MAX_FIELDS {
        return Err(format!(
            "too many redaction fields: {} (limit {MAX_FIELDS})",
            fields.len()
        ));
    }
    let mut parsed = Vec::new();
    for field in fields {
        let field = RedactionField::parse(field)?;
        if !parsed.contains(&field) {
            parsed.push(field);
        }
    }
    Ok(parsed)
}

/// Returns the stable redacted form of `value`.
pub fn redact_text(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{REDACTED_PREFIX}{}", hex::encode(&digest[..8]))
}

fn has(fields: &[RedactionField], field: RedactionField) -> bool {
    fields.contains(&field)
}

fn redact_finding(finding: &mut Finding, fields: &[RedactionField]) {
    if has(fields, RedactionField::FindingTitle) {
        finding.title = redact_text(&finding.title);
    }
    if has(fields, RedactionField::FindingDescription) {
        finding.description = redact_text(&finding.description);
    }
    if has(fields, RedactionField::FindingEvidence) {
        finding.evidence = redact_text(&finding.evidence);
    }
    if has(fields, RedactionField::FindingRemediation) {
        finding.remediation = redact_text(&finding.remediation);
    }
    if has(fields, RedactionField::FindingLocationFile) {
        let file = finding.location.file.to_string_lossy().replace('\\', "/");
        finding.location.file = redact_text(&file).into();
    }
}

/// Returns a redacted copy of `outcome` for rendering.
///
/// The original outcome is untouched, so fingerprints, matching, the exit gate
/// and baselines are unaffected.
pub fn redact(outcome: &ScanOutcome, fields: &[RedactionField]) -> ScanOutcome {
    let mut redacted = outcome.clone();
    if has(fields, RedactionField::ProjectRoot) {
        redacted.project.root = redact_text(&outcome.project.root.to_string_lossy()).into();
    }
    for finding in &mut redacted.findings {
        redact_finding(finding, fields);
    }
    for suppressed in &mut redacted.suppressed {
        redact_finding(&mut suppressed.finding, fields);
        redact_suppression_info(&mut suppressed.suppression, fields);
    }
    for suppression in &mut redacted.suppressions {
        if has(fields, RedactionField::SuppressionReason) {
            suppression.reason = suppression.reason.as_deref().map(redact_text);
        }
        if has(fields, RedactionField::SuppressionFile) {
            let file = suppression.file_label();
            suppression.file = redact_text(&file).into();
        }
    }
    for suppression in &mut redacted.config_suppressions {
        if has(fields, RedactionField::SuppressionReason) {
            suppression.reason = suppression.reason.as_deref().map(redact_text);
        }
    }
    for waiver in &mut redacted.waivers {
        if has(fields, RedactionField::WaiverOwner) {
            waiver.owner = redact_text(&waiver.owner);
        }
        if has(fields, RedactionField::WaiverReason) {
            waiver.reason = redact_text(&waiver.reason);
        }
    }
    redact_config_suppression_audit(&mut redacted, fields);
    for diagnostic in &mut redacted.diagnostics {
        if has(fields, RedactionField::DiagnosticMessage) {
            diagnostic.message = redact_text(&diagnostic.message);
        }
        if has(fields, RedactionField::DiagnosticPath) {
            diagnostic.path = diagnostic
                .path
                .as_ref()
                .map(|path| redact_text(&path.to_string_lossy()).into());
        }
    }
    redacted
}

fn redact_suppression_info(info: &mut crate::engine::SuppressionInfo, fields: &[RedactionField]) {
    if has(fields, RedactionField::SuppressionReason) {
        info.reason = info.reason.as_deref().map(redact_text);
    }
    if has(fields, RedactionField::SuppressionFile) {
        info.file = redact_text(&info.file);
    }
    if has(fields, RedactionField::WaiverOwner) {
        info.owner = info.owner.as_deref().map(redact_text);
    }
}

fn redact_config_suppression_audit(outcome: &mut ScanOutcome, fields: &[RedactionField]) {
    if has(fields, RedactionField::SuppressionReason) {
        for suppression in &mut outcome.config.suppressions {
            suppression.reason = suppression.reason.as_deref().map(redact_text);
        }
    }
    if has(fields, RedactionField::SuppressionFile) {
        for suppression in &mut outcome.config.suppressions {
            suppression.path = redact_text(&suppression.path);
        }
    }
    for waiver in &mut outcome.config.waivers {
        if has(fields, RedactionField::WaiverOwner) {
            waiver.owner = redact_text(&waiver.owner);
        }
        if has(fields, RedactionField::WaiverReason) {
            waiver.reason = redact_text(&waiver.reason);
        }
    }
}

/// Redacts a baseline comparison report in place.
pub fn redact_baseline(baseline: &mut BaselineReport, fields: &[RedactionField]) {
    for finding in &mut baseline.resolved_findings {
        if has(fields, RedactionField::FindingTitle) {
            finding.title = redact_text(&finding.title);
        }
        if has(fields, RedactionField::FindingLocationFile) {
            finding.file = redact_text(&finding.file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::confidence::Confidence;
    use crate::engine::{
        ConfigSuppressionReport, ScanStats, SuppressedFinding, SuppressionInfo, SuppressionSource,
        WaiverReport,
    };
    use crate::finding::SourceLocation;
    use crate::model::{Diagnostic, DiagnosticCode, Project, ProjectKind, SorobanInfo};
    use crate::severity::Severity;
    use std::path::PathBuf;

    fn finding() -> Finding {
        Finding {
            rule_id: "SS-001".to_string(),
            title: "Missing authorization".to_string(),
            description: "secret design detail".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            category: Category::Authorization,
            location: SourceLocation::new("src/secret/vault.rs", 7),
            evidence: "env.storage().set(&KEY, &admin)".to_string(),
            remediation: "call require_auth".to_string(),
            references: vec![],
            fingerprint: "stable-fingerprint".to_string(),
        }
    }

    fn outcome() -> ScanOutcome {
        let suppression = |reason: &str| SuppressionInfo {
            file: "src/secret/vault.rs".to_string(),
            line: 7,
            rules: "SS-001".to_string(),
            reason: Some(reason.to_string()),
            source: SuppressionSource::Config,
            path: Some("src/secret/**".to_string()),
            owner: None,
            expires: None,
        };
        ScanOutcome {
            project: Project {
                root: PathBuf::from("/home/alice/secret"),
                kind: ProjectKind::ConfirmedSoroban,
                manifests: vec![],
                soroban: SorobanInfo::default(),
                target: None,
                source_files: 1,
                diagnostics: vec![],
            },
            findings: vec![finding()],
            diagnostics: vec![Diagnostic::error(
                DiagnosticCode::InvalidWaiver,
                "secret diagnostic detail",
                Some(PathBuf::from("src/secret/vault.rs")),
            )],
            stats: ScanStats::default(),
            config: crate::config::ScanConfig::default(),
            suppressions: vec![],
            suppressed: vec![SuppressedFinding {
                finding: finding(),
                suppression: suppression("secret suppression reason"),
            }],
            config_suppressions: vec![ConfigSuppressionReport {
                path: "src/secret/**".to_string(),
                rule: "SS-001".to_string(),
                reason: Some("secret configured reason".to_string()),
                matched: 1,
                findings_suppressed: 1,
                applied: true,
            }],
            waivers: vec![WaiverReport {
                path: "src/secret/**".to_string(),
                rule: "SS-001".to_string(),
                owner: "alice@example.com".to_string(),
                reason: "secret waiver reason".to_string(),
                expires: "2999-12-31".to_string(),
                expired: false,
                matched: 1,
                findings_suppressed: 0,
                applied: false,
            }],
            truncation: None,
            rule_timings: vec![],
        }
    }

    fn all_fields() -> Vec<RedactionField> {
        validate_fields(&[
            "project.root".to_string(),
            "finding.title".to_string(),
            "finding.description".to_string(),
            "finding.evidence".to_string(),
            "finding.remediation".to_string(),
            "finding.location.file".to_string(),
            "suppression.reason".to_string(),
            "suppression.file".to_string(),
            "waiver.owner".to_string(),
            "waiver.reason".to_string(),
            "diagnostic.message".to_string(),
            "diagnostic.path".to_string(),
        ])
        .unwrap()
    }

    #[test]
    fn redaction_hashes_top_level_and_nested_fields() {
        let redacted = redact(&outcome(), &all_fields());
        let finding = &redacted.findings[0];
        assert!(finding.evidence.starts_with(REDACTED_PREFIX));
        assert!(finding
            .location
            .file
            .to_string_lossy()
            .starts_with(REDACTED_PREFIX));
        assert_eq!(finding.fingerprint, "stable-fingerprint");
        assert_eq!(finding.rule_id, "SS-001");
        assert_eq!(finding.location.line, 7);

        let suppressed = &redacted.suppressed[0];
        assert!(suppressed.finding.evidence.starts_with(REDACTED_PREFIX));
        assert!(suppressed
            .suppression
            .reason
            .as_deref()
            .unwrap()
            .starts_with(REDACTED_PREFIX));
        assert!(suppressed.suppression.file.starts_with(REDACTED_PREFIX));

        assert!(redacted.waivers[0].owner.starts_with(REDACTED_PREFIX));
        assert!(redacted.config_suppressions[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with(REDACTED_PREFIX));
        assert!(redacted.diagnostics[0].message.starts_with(REDACTED_PREFIX));
        assert!(redacted.diagnostics[0]
            .path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .starts_with(REDACTED_PREFIX));
        assert!(redacted
            .project
            .root
            .to_string_lossy()
            .starts_with(REDACTED_PREFIX));
    }

    #[test]
    fn redaction_is_deterministic_and_selective() {
        let fields = validate_fields(&["finding.evidence".to_string()]).unwrap();
        let first = redact(&outcome(), &fields);
        let second = redact(&outcome(), &fields);
        assert_eq!(first.findings[0].evidence, second.findings[0].evidence);
        assert_eq!(first.findings[0].title, "Missing authorization");
        assert_eq!(
            first.findings[0].location.file,
            PathBuf::from("src/secret/vault.rs")
        );
    }

    #[test]
    fn redaction_rejects_unknown_and_excessive_fields() {
        assert!(validate_fields(&["nope".to_string()]).is_err());
        let too_many = vec!["finding.evidence".to_string(); MAX_FIELDS + 1];
        assert!(validate_fields(&too_many).is_err());
    }
}
