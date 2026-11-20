//! The rule interface and metadata.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::severity::Severity;

/// Static metadata describing a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadata {
    /// Stable rule identifier (for example `SS-001`).
    pub id: &'static str,
    /// Short title.
    pub title: &'static str,
    /// Description of the problem.
    pub description: &'static str,
    /// Category.
    pub category: Category,
    /// Default severity.
    pub default_severity: Severity,
    /// Default confidence.
    pub default_confidence: Confidence,
    /// Remediation guidance.
    pub remediation: &'static str,
    /// External references.
    pub references: &'static [&'static str],
    /// Whether the rule is deprecated.
    ///
    /// A deprecated rule keeps its stable id and metadata so existing baselines
    /// and configuration stay resolvable, but it is excluded from default
    /// execution. See `docs/rules/deprecation.md` for the lifecycle.
    pub deprecated: bool,
}

impl RuleMetadata {
    /// Creates metadata without references.
    pub fn new(
        id: &'static str,
        title: &'static str,
        description: &'static str,
        category: Category,
        default_severity: Severity,
        default_confidence: Confidence,
        remediation: &'static str,
    ) -> Self {
        RuleMetadata {
            id,
            title,
            description,
            category,
            default_severity,
            default_confidence,
            remediation,
            references: &[],
            deprecated: false,
        }
    }

    /// Attaches references.
    pub fn with_references(mut self, references: &'static [&'static str]) -> Self {
        self.references = references;
        self
    }

    /// Marks the rule as deprecated.
    ///
    /// Deprecated rules keep their id so baselines and configuration remain
    /// resolvable, but they are skipped unless explicitly re-enabled.
    pub fn with_deprecated(mut self, deprecated: bool) -> Self {
        self.deprecated = deprecated;
        self
    }

    /// Whether this rule is deprecated.
    pub fn is_deprecated(&self) -> bool {
        self.deprecated
    }
}

/// A security rule.
///
/// Implementations must be deterministic and must never fabricate findings or
/// source locations. A rule observes the [`AnalysisContext`] and appends any
/// findings it can justify with concrete evidence.
pub trait Rule: Send + Sync {
    /// Returns this rule's metadata.
    fn metadata(&self) -> &RuleMetadata;

    /// Analyzes the context, appending findings.
    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>);

    /// Whether the rule is enabled by default.
    ///
    /// Deprecated rules are skipped by default. Override this only for rules
    /// that are intentionally opt-in for another reason.
    fn enabled_by_default(&self) -> bool {
        !self.metadata().is_deprecated()
    }

    /// Whether the rule only makes sense for Soroban projects.
    ///
    /// Defaults to `true`: the built-in detectors model Soroban semantics.
    /// A future generic-Rust rule can override this to keep running in
    /// generic mode.
    fn soroban_only(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_builder_attaches_references() {
        let meta = RuleMetadata::new(
            "SS-999",
            "Test",
            "desc",
            Category::Authorization,
            Severity::High,
            Confidence::Medium,
            "fix it",
        )
        .with_references(&["https://example.com"]);
        assert_eq!(meta.id, "SS-999");
        assert_eq!(meta.references.len(), 1);
        assert_eq!(meta.default_confidence, Confidence::Medium);
        assert!(!meta.is_deprecated());
    }

    #[test]
    fn deprecated_metadata_is_flagged_and_opt_out_of_default_execution() {
        struct DeprecatedRule {
            meta: RuleMetadata,
        }

        impl Rule for DeprecatedRule {
            fn metadata(&self) -> &RuleMetadata {
                &self.meta
            }
            fn analyze(&self, _ctx: &AnalysisContext<'_>, _out: &mut Vec<Finding>) {}
        }

        let rule = DeprecatedRule {
            meta: RuleMetadata::new(
                "SS-999",
                "Retired",
                "desc",
                Category::Authorization,
                Severity::Low,
                Confidence::Low,
                "upgrade",
            )
            .with_deprecated(true),
        };
        assert!(rule.metadata().is_deprecated());
        assert!(!rule.enabled_by_default());
    }
}
