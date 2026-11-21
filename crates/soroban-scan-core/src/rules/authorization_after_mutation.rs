//! SS-017: authorization after a state mutation.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-017",
    title: "Authorization after state mutation",
    description: "A contract entry point mutates storage before calling \
`require_auth`. The authorization check must run before the effect, otherwise a \
rejected call may already have changed state on some paths and the ordering \
indicates a logic bug.",
    category: Category::Authorization,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Authorize the caller at the start of the entry point, before \
any storage read or write that depends on the caller. Call `require_auth` or \
`require_auth_for_args` first, then perform the state change.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security/authorization"],
};

/// Detects storage mutations that precede `require_auth`.
pub struct AuthorizationAfterMutation;

impl Rule for AuthorizationAfterMutation {
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
                if !func.is_public {
                    continue;
                }
                let facts = ctx.facts_for_function(source, &func);
                let earliest_auth = facts
                    .method_calls
                    .iter()
                    .filter(|call| {
                        call.name == "require_auth" || call.name == "require_auth_for_args"
                    })
                    .map(|call| call.start_byte)
                    .min();
                let Some(auth_byte) = earliest_auth else {
                    continue;
                };
                for mutation in facts
                    .storage_mutations()
                    .into_iter()
                    .filter(|mutation| mutation.start_byte < auth_byte)
                {
                    let location = location_for(ctx, source, mutation.line, mutation.column);
                    let evidence = format!(
                        "storage mutation before authorization in `{}`: {}",
                        func.name, mutation.text
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
    fn flags_mutation_before_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address, value: u32) {
                    env.storage().persistent().set(&DataKey::Value, &value);
                    admin.require_auth();
                }
            }
            "#,
            Box::new(AuthorizationAfterMutation),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-017");
        assert!(findings[0].evidence.contains("before authorization"));
    }

    #[test]
    fn does_not_flag_auth_before_mutation() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address, value: u32) {
                    admin.require_auth();
                    env.storage().persistent().set(&DataKey::Value, &value);
                }
            }
            "#,
            Box::new(AuthorizationAfterMutation),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_without_authorization() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, value: u32) {
                    env.storage().persistent().set(&DataKey::Value, &value);
                }
            }
            "#,
            Box::new(AuthorizationAfterMutation),
        );
        assert!(findings.is_empty());
    }
}
