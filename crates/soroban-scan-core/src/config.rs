//! Scan and rule configuration.
//!
//! Repository-provided configuration is treated as untrusted data. No option
//! here can enable code execution or network access.

use std::collections::BTreeMap;
use std::path::Path;

use globset::Glob;
use serde::{Deserialize, Deserializer, Serialize};

use crate::ai::AiConfig;
use crate::category::Category;
use crate::confidence::Confidence;
use crate::severity::Severity;

/// Deserializes category names, accepting both kebab-case and snake_case.
///
/// Categories are validated here so an unknown name is a configuration error
/// rather than a silently ignored filter.
fn deserialize_categories<'de, D>(deserializer: D) -> Result<Vec<Category>, D::Error>
where
    D: Deserializer<'de>,
{
    let names = Vec::<String>::deserialize(deserializer)?;
    names
        .into_iter()
        .map(|name| name.parse::<Category>().map_err(serde::de::Error::custom))
        .collect()
}

/// Rule selection and overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesConfig {
    /// Rule ids to disable.
    pub disabled: Vec<String>,
    /// If non-empty, only these rule ids are enabled.
    pub enabled: Vec<String>,
    /// Categories to disable.
    #[serde(deserialize_with = "deserialize_categories")]
    pub disabled_categories: Vec<Category>,
    /// If non-empty, only rules in these categories are enabled.
    #[serde(deserialize_with = "deserialize_categories")]
    pub enabled_categories: Vec<Category>,
    /// Per-rule severity overrides.
    pub severity_overrides: BTreeMap<String, Severity>,
    /// Per-rule confidence overrides.
    pub confidence_overrides: BTreeMap<String, Confidence>,
    /// Optional per-rule wall-clock budget in milliseconds.
    ///
    /// Disabled by default. When set, each rule runs on a worker thread and is
    /// abandoned if it exceeds the budget; the engine emits a diagnostic and
    /// continues with the remaining rules. The budget is best-effort: a rule
    /// that has already started may keep running in the background until it
    /// returns, but its findings are discarded.
    #[serde(rename = "time_budget_ms", alias = "rule_time_budget_ms")]
    pub rule_time_budget_ms: Option<u64>,
}

impl RulesConfig {
    /// Returns true if the rule id is enabled under this configuration.
    pub fn is_enabled(&self, id: &str) -> bool {
        if self.disabled.iter().any(|r| r == id) {
            return false;
        }
        if !self.enabled.is_empty() {
            return self.enabled.iter().any(|r| r == id);
        }
        true
    }

    /// Returns true if the category is enabled under this configuration.
    ///
    /// Disabled categories always win. When `enabled_categories` is non-empty,
    /// a rule must also belong to one of the listed categories.
    pub fn is_category_enabled(&self, category: Category) -> bool {
        if self.disabled_categories.contains(&category) {
            return false;
        }
        if !self.enabled_categories.is_empty() {
            return self.enabled_categories.contains(&category);
        }
        true
    }

    /// Returns true if a rule is enabled by id and category.
    pub fn is_rule_enabled(&self, id: &str, category: Category) -> bool {
        self.is_enabled(id) && self.is_category_enabled(category)
    }
}

/// Literal that matches every rule in a configured suppression.
pub const ALL_SUPPRESSION_RULES: &str = "all";

/// Returns true when `token` is a valid `SS-###` rule id.
pub fn is_valid_rule_id(token: &str) -> bool {
    let token = token.trim();
    token.len() == 6
        && token
            .get(..3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("SS-"))
        && token[3..].chars().all(|c| c.is_ascii_digit())
}

/// A path- and rule-scoped suppression from configuration.
///
/// Suppressions are auditable: every entry is reported, including entries that
/// match no finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuppressionRule {
    /// Relative glob matched against root-relative finding paths.
    pub path: String,
    /// Rule id to suppress, or `all`.
    pub rule: String,
    /// Optional audit reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SuppressionRule {
    /// Validates the path and rule.
    pub fn validate(&self) -> Result<(), String> {
        let path = self.path.trim();
        if path.is_empty() {
            return Err("path must not be empty".to_string());
        }
        if path.starts_with('/') || path.starts_with('\\') || Path::new(path).is_absolute() {
            return Err("path must be relative".to_string());
        }
        if path.split(['/', '\\']).any(|component| component == "..") {
            return Err("path must not contain '..'".to_string());
        }
        Glob::new(path).map_err(|error| format!("path is not a valid glob: {error}"))?;

        let rule = self.rule.trim();
        if rule.is_empty() {
            return Err("rule must not be empty".to_string());
        }
        if !rule.eq_ignore_ascii_case(ALL_SUPPRESSION_RULES) && !is_valid_rule_id(rule) {
            return Err(format!(
                "rule must be 'all' or a rule id such as 'SS-001', got '{rule}'"
            ));
        }
        Ok(())
    }

    /// Returns true when this entry's rule covers `rule_id`.
    pub fn matches_rule(&self, rule_id: &str) -> bool {
        self.rule.eq_ignore_ascii_case(ALL_SUPPRESSION_RULES)
            || self.rule.trim().eq_ignore_ascii_case(rule_id)
    }

    /// Stable rule label used in reports.
    pub fn rule_label(&self) -> String {
        if self.rule.eq_ignore_ascii_case(ALL_SUPPRESSION_RULES) {
            ALL_SUPPRESSION_RULES.to_string()
        } else {
            self.rule.trim().to_ascii_uppercase()
        }
    }
}

/// A time-limited suppression from configuration.
///
/// Unlike a plain suppression, a waiver must name an owner, a reason, and an
/// expiry date (`YYYY-MM-DD`, UTC). Once the expiry date is in the past the
/// waiver stops suppressing findings and is reported as an error, so an
/// accepted risk cannot be hidden forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaiverRule {
    /// Relative glob matched against root-relative finding paths.
    pub path: String,
    /// Rule id to waive, or `all`.
    pub rule: String,
    /// Accountable owner of the accepted risk.
    pub owner: String,
    /// Audit reason. Required and must not be empty.
    pub reason: String,
    /// Last day the waiver applies, as a UTC `YYYY-MM-DD` date.
    pub expires: String,
}

impl WaiverRule {
    /// Validates the path, rule, owner, reason, and expiry date.
    pub fn validate(&self) -> Result<(), String> {
        SuppressionRule {
            path: self.path.clone(),
            rule: self.rule.clone(),
            reason: Some(self.reason.clone()),
        }
        .validate()?;
        if self.owner.trim().is_empty() {
            return Err("owner must not be empty".to_string());
        }
        if self.reason.trim().is_empty() {
            return Err("reason must not be empty".to_string());
        }
        validate_iso_date(&self.expires)
    }

    /// Returns true when this waiver's rule covers `rule_id`.
    pub fn matches_rule(&self, rule_id: &str) -> bool {
        self.rule.eq_ignore_ascii_case(ALL_SUPPRESSION_RULES)
            || self.rule.trim().eq_ignore_ascii_case(rule_id)
    }

    /// Stable rule label used in reports.
    pub fn rule_label(&self) -> String {
        if self.rule.eq_ignore_ascii_case(ALL_SUPPRESSION_RULES) {
            ALL_SUPPRESSION_RULES.to_string()
        } else {
            self.rule.trim().to_ascii_uppercase()
        }
    }

    /// Returns true when the waiver has expired on `today` (`YYYY-MM-DD`).
    ///
    /// ISO dates in this format compare lexicographically, so no clock or
    /// calendar computation is needed at the comparison site. `today` is
    /// supplied by the caller so expiry is testable with fixed dates.
    pub fn is_expired_on(&self, today: &str) -> bool {
        self.expires.trim() < today.trim()
    }
}

/// Validates a UTC `YYYY-MM-DD` date.
pub(crate) fn validate_iso_date(value: &str) -> Result<(), String> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return Err(format!("expires must be a YYYY-MM-DD date, got '{value}'"));
    }
    let year = value[0..4]
        .parse::<u32>()
        .map_err(|_| format!("expires must be a YYYY-MM-DD date, got '{value}'"))?;
    let month = value[5..7]
        .parse::<u32>()
        .map_err(|_| format!("expires must be a YYYY-MM-DD date, got '{value}'"))?;
    let day = value[8..10]
        .parse::<u32>()
        .map_err(|_| format!("expires must be a YYYY-MM-DD date, got '{value}'"))?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return Err(format!("expires has an invalid month: '{value}'")),
    };
    if day == 0 || day > days {
        return Err(format!("expires has an invalid day: '{value}'"));
    }
    Ok(())
}

/// Returns the current UTC date as `YYYY-MM-DD`.
///
/// The system clock is read once per scan; waiver decisions use the UTC date,
/// never a local timezone.
pub fn today_utc() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    utc_date_from_unix(seconds)
}

/// Converts Unix seconds to a UTC `YYYY-MM-DD` date (Howard Hinnant's algorithm).
pub(crate) fn utc_date_from_unix(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}")
}

/// Complete scan configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    /// Minimum severity to report.
    pub min_severity: Severity,
    /// Minimum confidence to report.
    pub min_confidence: Confidence,
    /// Glob patterns (relative to the scan root) to exclude from discovery.
    pub exclude: Vec<String>,
    /// Skip items gated behind `#[cfg(test)]` and test directories.
    pub exclude_tests: bool,
    /// Keep items gated behind `#[cfg(test)]` (they are skipped by default).
    /// Has no effect when `exclude_tests` is set.
    pub include_cfg_test: bool,
    /// Exclude files carrying generated-code markers instead of marking them.
    pub exclude_generated: bool,
    /// Whether to follow symbolic links during discovery.
    pub follow_symlinks: bool,
    /// Minimum supported `soroban-sdk` version for the SS-015 policy check.
    pub minimum_soroban_sdk: String,
    /// Path- and rule-scoped suppressions.
    pub suppressions: Vec<SuppressionRule>,
    /// Time-limited, owned suppressions. Expired waivers stop applying and are
    /// reported as errors.
    pub waivers: Vec<WaiverRule>,
    /// Report fields to replace with a stable hash at render time.
    pub redact: Vec<String>,
    /// Rule selection and overrides.
    pub rules: RulesConfig,
    /// Optional assistance layer configuration (disabled by default).
    pub ai: AiConfig,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            min_severity: Severity::Info,
            min_confidence: Confidence::Low,
            exclude: Vec::new(),
            exclude_tests: false,
            include_cfg_test: false,
            exclude_generated: false,
            follow_symlinks: false,
            minimum_soroban_sdk: "21.0.0".to_string(),
            suppressions: Vec::new(),
            waivers: Vec::new(),
            redact: Vec::new(),
            rules: RulesConfig::default(),
            ai: AiConfig::default(),
        }
    }
}

impl ScanConfig {
    /// Builds [`crate::discovery::DiscoveryOptions`] from this configuration.
    pub fn discovery_options(&self) -> crate::discovery::DiscoveryOptions {
        crate::discovery::DiscoveryOptions {
            follow_symlinks: self.follow_symlinks,
            exclude: self.exclude.clone(),
            exclude_tests: self.exclude_tests,
            include_cfg_test: self.include_cfg_test,
            exclude_generated: self.exclude_generated,
        }
    }

    /// Validates configured suppressions and assistance parameters.
    pub fn validate(&self) -> Result<(), crate::error::ScanError> {
        for (index, suppression) in self.suppressions.iter().enumerate() {
            suppression.validate().map_err(|error| {
                crate::error::ScanError::Config(format!("invalid suppressions[{index}]: {error}"))
            })?;
        }
        for (index, waiver) in self.waivers.iter().enumerate() {
            waiver.validate().map_err(|error| {
                crate::error::ScanError::Config(format!("invalid waivers[{index}]: {error}"))
            })?;
        }
        crate::redaction::validate_fields(&self.redact)
            .map_err(|error| crate::error::ScanError::Config(format!("invalid redact: {error}")))?;
        self.ai
            .validate()
            .map_err(|error| crate::error::ScanError::Config(format!("invalid config: {error}")))?;
        Ok(())
    }

    /// Parses and validates a configuration from TOML text.
    pub fn from_toml(text: &str) -> Result<Self, crate::error::ScanError> {
        // toml 1.x's `Value::from_str` parses one value, not a document.
        let value = toml::from_str::<toml::Value>(text)
            .map_err(|e| crate::error::ScanError::Config(format!("invalid config TOML: {e}")))?;
        let config: Self = value
            .try_into()
            .map_err(|e| crate::error::ScanError::Config(format!("invalid config: {e}")))?;
        config.validate()?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_permissive_and_safe() {
        let config = ScanConfig::default();
        assert_eq!(config.min_severity, Severity::Info);
        assert_eq!(config.min_confidence, Confidence::Low);
        assert!(!config.follow_symlinks);
    }

    #[test]
    fn rule_enable_disable_logic() {
        let rules = RulesConfig::default();
        assert!(rules.is_enabled("SS-001"));

        let rules = RulesConfig {
            disabled: vec!["SS-001".into()],
            ..RulesConfig::default()
        };
        assert!(!rules.is_enabled("SS-001"));

        let only = RulesConfig {
            enabled: vec!["SS-002".into()],
            ..RulesConfig::default()
        };
        assert!(only.is_enabled("SS-002"));
        assert!(!only.is_enabled("SS-001"));
    }

    #[test]
    fn parses_toml_config() {
        let config = ScanConfig::from_toml(
            r#"
min_severity = "medium"
min_confidence = "low"
exclude = ["vendor/**"]

[rules]
disabled = ["SS-010"]
"#,
        )
        .unwrap();
        assert_eq!(config.min_severity, Severity::Medium);
        assert!(!config.rules.is_enabled("SS-010"));
    }

    #[test]
    fn rule_time_budget_is_disabled_by_default_and_parses() {
        assert_eq!(RulesConfig::default().rule_time_budget_ms, None);

        let config = ScanConfig::from_toml(
            r#"
[rules]
time_budget_ms = 2500
"#,
        )
        .unwrap();
        assert_eq!(config.rules.rule_time_budget_ms, Some(2500));
    }

    #[test]
    fn parses_and_applies_category_filters() {
        let config = ScanConfig::from_toml(
            r#"
[rules]
disabled_categories = ["resource-usage"]
enabled_categories = ["authorization", "storage"]
"#,
        )
        .unwrap();

        assert_eq!(
            config.rules.disabled_categories,
            vec![Category::ResourceUsage]
        );
        assert_eq!(
            config.rules.enabled_categories,
            vec![Category::Authorization, Category::Storage]
        );
        assert!(!config.rules.is_category_enabled(Category::ResourceUsage));
        assert!(config.rules.is_category_enabled(Category::Authorization));
        assert!(config.rules.is_category_enabled(Category::Storage));
        assert!(!config.rules.is_category_enabled(Category::Arithmetic));
    }

    #[test]
    fn accepts_snake_case_category_names() {
        let config = ScanConfig::from_toml(
            r#"
[rules]
disabled_categories = ["resource_usage", "access_control"]
"#,
        )
        .unwrap();
        assert_eq!(
            config.rules.disabled_categories,
            vec![Category::ResourceUsage, Category::AccessControl]
        );
    }

    #[test]
    fn rejects_unknown_category() {
        let err = ScanConfig::from_toml(
            r#"
[rules]
disabled_categories = ["nonsense"]
"#,
        )
        .unwrap_err();
        assert!(matches!(err, crate::error::ScanError::Config(_)));
        assert!(
            err.to_string().contains("unknown category"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let err = ScanConfig::from_toml("mystery = true").unwrap_err();
        assert!(matches!(err, crate::error::ScanError::Config(_)));
    }

    #[test]
    fn parses_validated_ai_parameters() {
        let config = ScanConfig::from_toml(
            r#"
[ai]
enabled = false
provider = "openai"
model = "example-model"
temperature = 0.2
max_output_tokens = 2048
"#,
        )
        .unwrap();
        assert_eq!(config.ai.temperature, 0.2);
        assert_eq!(config.ai.max_output_tokens, 2048);
        assert_eq!(config.ai.provider.as_deref(), Some("openai"));
    }

    #[test]
    fn defaults_include_conservative_ai_parameters() {
        let config = ScanConfig::default();
        assert_eq!(config.ai.temperature, 0.0);
        assert_eq!(config.ai.max_output_tokens, 1024);
    }

    #[test]
    fn rejects_out_of_range_ai_parameters() {
        let cases = [
            ("[ai]\ntemperature = 1.5\n", "ai.temperature"),
            ("[ai]\ntemperature = -0.1\n", "ai.temperature"),
            ("[ai]\ntemperature = nan\n", "ai.temperature"),
            ("[ai]\nmax_output_tokens = 0\n", "ai.max_output_tokens"),
            ("[ai]\nmax_output_tokens = 9000\n", "ai.max_output_tokens"),
        ];
        for (text, field) in cases {
            let err = ScanConfig::from_toml(text).unwrap_err();
            assert!(matches!(err, crate::error::ScanError::Config(_)));
            assert!(
                err.to_string().contains(field),
                "expected {field} in error: {err}"
            );
        }
    }

    #[test]
    fn parses_suppression_array_of_tables() {
        let config = ScanConfig::from_toml(
            r#"
exclude_generated = true

[[suppressions]]
path = "src/generated/**"
rule = "all"
reason = "generated by the SDK"

[[suppressions]]
path = "tests/**"
rule = "SS-001"

[rules]
disabled = ["SS-010"]
"#,
        )
        .unwrap();

        assert!(config.exclude_generated);
        assert_eq!(config.suppressions.len(), 2);
        let first = &config.suppressions[0];
        assert_eq!(first.path, "src/generated/**");
        assert_eq!(first.rule, "all");
        assert_eq!(first.reason.as_deref(), Some("generated by the SDK"));
        assert!(first.matches_rule("SS-029"));
        let second = &config.suppressions[1];
        assert_eq!(second.rule, "SS-001");
        assert_eq!(second.reason, None);
        assert!(second.matches_rule("ss-001"));
        assert!(!second.matches_rule("SS-002"));
    }

    #[test]
    fn validates_suppression_paths_and_rules() {
        let invalid = [
            r#"[[suppressions]]
path = ""
rule = "SS-001"
"#,
            r#"[[suppressions]]
path = "/absolute/**"
rule = "SS-001"
"#,
            r#"[[suppressions]]
path = "../outside/**"
rule = "SS-001"
"#,
            r#"[[suppressions]]
path = "src/["
rule = "SS-001"
"#,
            r#"[[suppressions]]
path = "src/**"
rule = "SS-1"
"#,
            r#"[[suppressions]]
path = "src/**"
rule = ""
"#,
        ];
        for text in invalid {
            let err = ScanConfig::from_toml(text).unwrap_err();
            assert!(matches!(err, crate::error::ScanError::Config(_)));
            assert!(
                err.to_string().contains("suppressions"),
                "unexpected error for {text:?}: {err}"
            );
        }
    }

    #[test]
    fn validates_loaded_suppressions_directly() {
        let mut config = ScanConfig::default();
        config.suppressions.push(SuppressionRule {
            path: "src/generated/**".to_string(),
            rule: "all".to_string(),
            reason: None,
        });
        assert!(config.validate().is_ok());

        config.suppressions[0].path = "../escape/**".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn parses_waivers_with_owner_reason_and_expiry() {
        let config = ScanConfig::from_toml(
            r#"
[[waivers]]
path = "src/legacy/**"
rule = "SS-001"
owner = "security-team"
reason = "migration tracked in SEC-42"
expires = "2030-06-30"
"#,
        )
        .unwrap();
        assert_eq!(config.waivers.len(), 1);
        let waiver = &config.waivers[0];
        assert_eq!(waiver.owner, "security-team");
        assert_eq!(waiver.reason, "migration tracked in SEC-42");
        assert!(waiver.matches_rule("ss-001"));
        assert!(!waiver.is_expired_on("2030-06-30"));
        assert!(waiver.is_expired_on("2030-07-01"));
    }

    #[test]
    fn waiver_requires_reason_owner_and_valid_expiry() {
        let cases = [
            (
                r#"
[[waivers]]
path = "src/**"
rule = "SS-001"
owner = "team"
expires = "2030-01-01"
"#,
                "missing field `reason`",
            ),
            (
                r#"
[[waivers]]
path = "src/**"
rule = "SS-001"
owner = "team"
reason = "   "
expires = "2030-01-01"
"#,
                "reason must not be empty",
            ),
            (
                r#"
[[waivers]]
path = "src/**"
rule = "SS-001"
owner = ""
reason = "documented"
expires = "2030-01-01"
"#,
                "owner must not be empty",
            ),
            (
                r#"
[[waivers]]
path = "src/**"
rule = "SS-001"
owner = "team"
reason = "documented"
expires = "2030-02-30"
"#,
                "invalid day",
            ),
            (
                r#"
[[waivers]]
path = "src/**"
rule = "SS-001"
owner = "team"
reason = "documented"
expires = "tomorrow"
"#,
                "YYYY-MM-DD",
            ),
        ];
        for (text, expected) in cases {
            let err = ScanConfig::from_toml(text).unwrap_err();
            assert!(matches!(err, crate::error::ScanError::Config(_)));
            assert!(
                err.to_string().contains(expected),
                "expected {expected:?} in {err}"
            );
            assert!(err.to_string().contains("waivers"), "{err}");
        }
    }

    #[test]
    fn utc_date_conversion_uses_fixed_epochs() {
        assert_eq!(utc_date_from_unix(0), "1970-01-01");
        assert_eq!(utc_date_from_unix(1_709_164_800), "2024-02-29");
        assert_eq!(utc_date_from_unix(1_735_689_599), "2024-12-31");
        assert_eq!(utc_date_from_unix(1_735_689_600), "2025-01-01");
    }

    #[test]
    fn parses_and_validates_redaction_fields() {
        let config = ScanConfig::from_toml(
            r#"
redact = ["finding.evidence", "finding.location.file", "suppression.reason"]
"#,
        )
        .unwrap();
        assert_eq!(config.redact.len(), 3);

        let err = ScanConfig::from_toml("redact = [\"not.a.field\"]").unwrap_err();
        assert!(matches!(err, crate::error::ScanError::Config(_)));
        assert!(err.to_string().contains("unknown redaction field"), "{err}");
    }

    #[test]
    fn discovery_options_carry_generated_exclusion() {
        let config = ScanConfig {
            exclude_generated: true,
            ..ScanConfig::default()
        };
        assert!(config.discovery_options().exclude_generated);
    }
}
