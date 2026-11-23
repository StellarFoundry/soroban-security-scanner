//! SS-036: deprecated SDK API usage.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{facts_from_file_with_imports, location_for};

/// A known deprecated Soroban SDK API.
pub struct DeprecatedApi {
    /// Receiver fragment that scopes the match (for example `logger`).
    pub receiver: &'static str,
    /// Method or function name.
    pub method: &'static str,
    /// SDK version that deprecated or removed the API.
    pub since: &'static str,
    /// Recommended replacement.
    pub replacement: &'static str,
}

/// The versioned table of deprecated SDK APIs. Keep this data-driven and add a
/// row with a version and replacement when an API is retired.
pub const DEPRECATED_APIS: &[DeprecatedApi] = &[
    DeprecatedApi {
        receiver: "logger",
        method: "log",
        since: "20.0.0",
        replacement: "env.events().publish(...)",
    },
    DeprecatedApi {
        receiver: "env",
        method: "budget",
        since: "20.0.0",
        replacement: "env.cost_estimate()",
    },
    DeprecatedApi {
        receiver: "Address",
        method: "random",
        since: "21.0.0",
        replacement: "derive the value from ledger state or validated caller input",
    },
];

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-036",
    title: "Deprecated SDK API usage",
    description: "The contract calls a Soroban SDK API that has been deprecated \
or removed. The code may fail to build against a newer SDK, and the old API can \
carry stale behavior or security assumptions.",
    category: Category::Dependencies,
    default_severity: Severity::Low,
    default_confidence: Confidence::Medium,
    remediation: "Use the documented replacement for the SDK version in use, then \
re-run the scanner after upgrading `soroban-sdk`.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security"],
};

/// Detects calls to deprecated SDK APIs.
pub struct DeprecatedSdkApiUsage;

impl Rule for DeprecatedSdkApiUsage {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        for source in ctx.sources() {
            let Some(file) = &source.syntax else {
                continue;
            };
            let facts = facts_from_file_with_imports(file, &source.imports);
            for call in facts.method_calls.iter().chain(facts.function_calls.iter()) {
                for api in DEPRECATED_APIS {
                    if call.name != api.method {
                        continue;
                    }
                    if !api.receiver.is_empty() && !call.context.contains(api.receiver) {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "deprecated `{}` API (since {}, use {}): {}",
                        api.method, api.since, api.replacement, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_deprecated_logger_log() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn entry(env: Env) {
                    env.logger().log("deprecated");
                }
            }
            "#,
            Box::new(DeprecatedSdkApiUsage),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-036");
        assert!(findings[0].evidence.contains("deprecated"));
    }

    #[test]
    fn flags_deprecated_budget_and_address_random() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn entry(env: Env) {
                    let _ = env.budget();
                    let _ = Address::random(&env);
                }
            }
            "#,
            Box::new(DeprecatedSdkApiUsage),
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn does_not_flag_current_apis() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn entry(env: Env) {
                    env.events().publish(("topic",), 1);
                    let _ = env.cost_estimate();
                }
            }
            "#,
            Box::new(DeprecatedSdkApiUsage),
        );
        assert!(findings.is_empty());
    }
}
