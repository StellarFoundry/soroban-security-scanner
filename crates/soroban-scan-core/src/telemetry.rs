//! Opt-in, privacy-bounded telemetry and crash-event payloads.
//!
//! The scanner transmits nothing by itself. This module defines the only data
//! that a caller may collect when telemetry is explicitly enabled: stable
//! enums, sizes, and counters. Source text, paths, rule evidence, messages,
//! tokens, and environment values have no field in the schema, so they cannot
//! leak through serialization.
//!
//! [`TelemetryConfig`] is disabled by default and [`TelemetryConfig::encode`]
//! refuses to produce an event until it is enabled.

use serde::{Deserialize, Serialize};

use crate::config::AnalysisMode;
use crate::engine::ScanOutcome;
use crate::error::ScanError;
use crate::model::ProjectKind;
use crate::severity::Severity;

/// Version of the telemetry event schema in this module.
pub const TELEMETRY_SCHEMA_VERSION: u32 = 1;
/// Maximum serialized size of one telemetry event (4 KiB).
pub const MAX_TELEMETRY_EVENT_BYTES: usize = 4 * 1024;
/// Maximum size of a telemetry configuration document (64 KiB).
pub const MAX_TELEMETRY_CONFIG_BYTES: usize = 64 * 1024;

/// Telemetry settings. Every field defaults off.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Explicit opt-in. Telemetry is never sent or encoded while false.
    pub enabled: bool,
}

/// Telemetry configuration or payload failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TelemetryError {
    /// The caller did not opt in.
    #[error("telemetry is disabled; explicit opt-in is required")]
    Disabled,
    /// The configuration is malformed or too large.
    #[error("invalid telemetry configuration")]
    InvalidConfiguration,
    /// A serialized event exceeded the payload bound.
    #[error("telemetry payload exceeds {limit} bytes")]
    PayloadTooLarge {
        /// Maximum accepted serialized size.
        limit: usize,
    },
}

/// The kind of telemetry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    /// A scan finished, with or without findings.
    ScanCompleted,
    /// A scan could not be completed.
    ScanFailed,
    /// The process crashed or aborted.
    Crash,
}

/// Coarse failure classes. Messages and paths are deliberately absent because
/// both can contain user source, credentials, or filesystem layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrashClass {
    /// Filesystem or other I/O failure.
    Io,
    /// A source or manifest could not be parsed.
    Parse,
    /// Configuration was invalid.
    Config,
    /// A baseline was invalid or incompatible.
    Baseline,
    /// An unknown rule id was requested.
    UnknownRule,
    /// A path was rejected as unsafe.
    UnsafePath,
}

impl CrashClass {
    /// Maps an error to its coarse class without copying its message.
    pub fn from_error(error: &ScanError) -> Self {
        match error {
            ScanError::Io { .. } => CrashClass::Io,
            ScanError::Parse { .. } => CrashClass::Parse,
            ScanError::Config(_) => CrashClass::Config,
            ScanError::Baseline(_) => CrashClass::Baseline,
            ScanError::UnknownRule(_) => CrashClass::UnknownRule,
            ScanError::UnsafePath(_) => CrashClass::UnsafePath,
        }
    }
}

/// Finding counts by severity. No finding text is included.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct SeverityTotals {
    /// Informational findings.
    pub info: usize,
    /// Low-severity findings.
    pub low: usize,
    /// Medium-severity findings.
    pub medium: usize,
    /// High-severity findings.
    pub high: usize,
    /// Critical findings.
    pub critical: usize,
}

impl SeverityTotals {
    fn from_outcome(outcome: &ScanOutcome) -> Self {
        let mut totals = Self::default();
        for finding in &outcome.findings {
            match finding.severity {
                Severity::Info => totals.info += 1,
                Severity::Low => totals.low += 1,
                Severity::Medium => totals.medium += 1,
                Severity::High => totals.high += 1,
                Severity::Critical => totals.critical += 1,
            }
        }
        totals
    }
}

/// Bounded counters from one scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScanSummary {
    /// Detected project kind.
    pub project_kind: ProjectKind,
    /// Effective analysis mode.
    pub analysis_mode: AnalysisMode,
    /// Files analyzed.
    pub files_analyzed: usize,
    /// Files that failed to parse.
    pub files_failed: usize,
    /// Rules executed.
    pub rules_run: usize,
    /// Rules that failed or panicked.
    pub rules_failed: usize,
    /// Rules abandoned after their time budget.
    pub rules_timed_out: usize,
    /// Gate finding counts by severity.
    pub findings: SeverityTotals,
}

/// One telemetry event. Every field is an enum, counter, or the fixed schema
/// version, so no free-form user data can be added by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TelemetryEvent {
    /// Schema version for collector compatibility.
    pub schema_version: u32,
    /// Event kind.
    pub kind: TelemetryEventKind,
    /// Scanner version.
    pub tool_version: &'static str,
    /// Present for scan events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<ScanSummary>,
    /// Present for crash events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crash: Option<CrashClass>,
}

impl TelemetryEvent {
    /// Builds a completed-scan event from a finished outcome.
    pub fn scan_completed(outcome: &ScanOutcome) -> Self {
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            kind: TelemetryEventKind::ScanCompleted,
            tool_version: crate::VERSION,
            scan: Some(ScanSummary {
                project_kind: outcome.project.kind,
                analysis_mode: outcome.stats.analysis_mode,
                files_analyzed: outcome.stats.files_analyzed,
                files_failed: outcome.stats.files_failed,
                rules_run: outcome.stats.rules_run,
                rules_failed: outcome.stats.rules_failed,
                rules_timed_out: outcome.stats.rules_timed_out,
                findings: SeverityTotals::from_outcome(outcome),
            }),
            crash: None,
        }
    }

    /// Builds a failed-scan event. The error message is never included.
    pub fn scan_failed(error: &ScanError) -> Self {
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            kind: TelemetryEventKind::ScanFailed,
            tool_version: crate::VERSION,
            scan: None,
            crash: Some(CrashClass::from_error(error)),
        }
    }

    /// Builds a crash event. The panic or error text is never included.
    pub fn crash(error: &ScanError) -> Self {
        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            kind: TelemetryEventKind::Crash,
            tool_version: crate::VERSION,
            scan: None,
            crash: Some(CrashClass::from_error(error)),
        }
    }
}

impl TelemetryConfig {
    /// Parses a `[telemetry]` table from a configuration document.
    ///
    /// Other top-level tables are ignored so this can read a dedicated
    /// telemetry file or a larger deployment configuration. Unknown keys
    /// inside `[telemetry]` are rejected.
    pub fn from_toml(text: &str) -> Result<Self, TelemetryError> {
        if text.len() > MAX_TELEMETRY_CONFIG_BYTES {
            return Err(TelemetryError::InvalidConfiguration);
        }
        let value: toml::Value =
            toml::from_str(text).map_err(|_| TelemetryError::InvalidConfiguration)?;
        let Some(table) = value.get("telemetry") else {
            return Ok(Self::default());
        };
        let table = table
            .as_table()
            .ok_or(TelemetryError::InvalidConfiguration)?;
        toml::Value::Table(table.clone())
            .try_into::<TelemetryConfig>()
            .map_err(|_| TelemetryError::InvalidConfiguration)
    }

    /// Serializes an event only when telemetry is explicitly enabled.
    pub fn encode(&self, event: &TelemetryEvent) -> Result<String, TelemetryError> {
        if !self.enabled {
            return Err(TelemetryError::Disabled);
        }
        let encoded =
            serde_json::to_string(event).map_err(|_| TelemetryError::InvalidConfiguration)?;
        if encoded.len() > MAX_TELEMETRY_EVENT_BYTES {
            return Err(TelemetryError::PayloadTooLarge {
                limit: MAX_TELEMETRY_EVENT_BYTES,
            });
        }
        Ok(encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::scan_source_str;
    use crate::registry::RuleRegistry;

    fn outcome() -> ScanOutcome {
        scan_source_str(
            "pub fn transfer(env: Env) { env.storage().persistent().set(&KEY, &1); }",
            "private/customer-contract/src/lib.rs",
            &ScanConfig::default(),
            &RuleRegistry::with_default_rules(),
        )
    }

    #[test]
    fn telemetry_is_disabled_by_default() {
        let config = TelemetryConfig::default();
        assert!(!config.enabled);
        assert_eq!(
            config.encode(&TelemetryEvent::scan_completed(&outcome())),
            Err(TelemetryError::Disabled)
        );
        assert_eq!(
            TelemetryConfig::from_toml("").unwrap(),
            TelemetryConfig::default()
        );
    }

    #[test]
    fn explicit_opt_in_encodes_a_bounded_event() {
        let config = TelemetryConfig::from_toml("[telemetry]\nenabled = true\n").unwrap();
        let encoded = config
            .encode(&TelemetryEvent::scan_completed(&outcome()))
            .unwrap();
        assert!(encoded.len() <= MAX_TELEMETRY_EVENT_BYTES);
        let value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(value["schema_version"], TELEMETRY_SCHEMA_VERSION);
        assert_eq!(value["kind"], "scan_completed");
        assert_eq!(value["scan"]["findings"]["critical"], 0);
    }

    #[test]
    fn scan_events_contain_no_paths_source_or_rule_evidence() {
        let config = TelemetryConfig { enabled: true };
        let encoded = config
            .encode(&TelemetryEvent::scan_completed(&outcome()))
            .unwrap();

        for secret in [
            "private/customer-contract",
            "customer-contract",
            "src/lib.rs",
            "transfer",
            "storage",
            "SS-",
            "persistent",
        ] {
            assert!(
                !encoded.contains(secret),
                "telemetry leaked {secret:?}: {encoded}"
            );
        }
    }

    #[test]
    fn crash_events_contain_no_message_or_path() {
        let error = ScanError::Config("token=ghp_secret at /home/user/repo".to_string());
        let config = TelemetryConfig { enabled: true };
        let encoded = config.encode(&TelemetryEvent::crash(&error)).unwrap();

        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap()["crash"],
            "config"
        );
        for secret in ["ghp_secret", "/home/user/repo", "token"] {
            assert!(
                !encoded.contains(secret),
                "crash telemetry leaked {secret:?}"
            );
        }
    }

    #[test]
    fn invalid_configuration_is_rejected() {
        for text in [
            "[telemetry]\nenabled = true\nretention_days = 90\n",
            "[telemetry]\nenabled = \"yes\"\n",
            "[telemetry]\nenabled = true\n[telemetry.extra]\nvalue = 1\n",
            "not toml",
        ] {
            assert_eq!(
                TelemetryConfig::from_toml(text),
                Err(TelemetryError::InvalidConfiguration),
                "{text:?}"
            );
        }
        assert_eq!(
            TelemetryConfig::from_toml(&" ".repeat(MAX_TELEMETRY_CONFIG_BYTES + 1)),
            Err(TelemetryError::InvalidConfiguration)
        );
    }
}
