//! SS-029: public test or debug hook exposed as a contract entry point.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-029",
    title: "Public test or debug hook in a contract entry point",
    description: "A public contract entry point is named like a test or debug \
backdoor (a `test`, `debug`, `dev`, `mock`, or `dummy` name segment). Backdoor \
entry points that remain callable in a production deployment let anyone invoke \
privileged behavior, and are a well-known way on-chain contracts are \
compromised. This is a name-based heuristic and may flag a legitimately named \
function.",
    category: Category::AccessControl,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Remove test/debug entry points before deployment, or gate them \
behind `#[cfg(test)]` or a compile-time feature so they cannot be called from a \
production build. Never ship a privileged function intended only for testing.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security"],
    deprecated: false,
};

/// Detects public entry points whose name looks like a test/debug hook.
pub struct PublicTestHooks;

/// Name segments that indicate a test/debug helper.
const SUSPICIOUS_SEGMENTS: &[&str] = &["test", "debug", "dev", "mock", "dummy"];

/// True when the name has a test/debug-like `_`-separated segment.
///
/// Segment matching avoids false positives from substrings such as `latest`.
fn is_test_or_debug_name(name: &str) -> bool {
    name.to_ascii_lowercase()
        .split('_')
        .any(|segment| SUSPICIOUS_SEGMENTS.contains(&segment))
}

impl Rule for PublicTestHooks {
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
            for func in contract_entry_functions(file) {
                if !func.is_public || !is_test_or_debug_name(&func.name) {
                    continue;
                }
                let location = location_for(ctx, source, func.line, func.column);
                let evidence = format!(
                    "public entry point `{}` looks like a test/debug hook",
                    func.name
                );
                out.push(Finding::new(&METADATA, location, evidence));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_debug_entry_point() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn debug_set_admin(env: Env, a: Address) {
                    env.storage().persistent().set(&K, &a);
                }
            }
            "#,
            Box::new(PublicTestHooks),
        );
        assert_eq!(findings[0].rule_id, "SS-029");
        assert!(findings[0].evidence.contains("debug_set_admin"));
    }

    #[test]
    fn does_not_flag_normal_names() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn transfer(env: Env, to: Address, amount: i128) {
                    to.require_auth();
                }
                pub fn latest(env: Env) -> u32 { 1 }
            }
            "#,
            Box::new(PublicTestHooks),
        );
        assert!(findings.is_empty());
    }
}
