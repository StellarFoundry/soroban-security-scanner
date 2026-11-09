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
    /// Whether this rule is deprecated and excluded from default execution.
    pub deprecated: bool,
}

impl RuleMetadata {
    /// Creates metadata without references.
    pub const fn new(
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
    pub const fn with_references(mut self, references: &'static [&'static str]) -> Self {
        self.references = references;
        self
    }

    /// Marks the rule as deprecated (or active).
    pub const fn with_deprecated(mut self, deprecated: bool) -> Self {
        self.deprecated = deprecated;
        self
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

    /// Whether the rule is enabled by default. Defaults to `!self.metadata().deprecated`.
    fn enabled_by_default(&self) -> bool {
        !self.metadata().deprecated
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
    }
}
