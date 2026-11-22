//! SS-037: competing authorization calls.

use std::collections::BTreeSet;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-037",
    title: "Competing authorization calls",
    description: "A contract entry point calls `require_auth` for two or more \
distinct actors. Multiple separate approvals in a single operation usually \
indicate confused authorization semantics: it is hard to tell which actor is \
actually required, and a missing check elsewhere may be masked. Legitimate \
multi-party flows exist, so review each finding in context.",
    category: Category::Authorization,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Prefer a single, explicit authorization for the actor whose \
operation this is, or bind all required parties through one documented multi-sig \
pattern. If the flow genuinely requires several independent approvals, document \
the policy and suppress the finding with a justified inline directive.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects entry points that authorize two or more distinct actors.
pub struct CompetingAuthorizationCalls;

impl Rule for CompetingAuthorizationCalls {
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
                let mut actors = BTreeSet::new();
                let mut first = None;
                for call in &facts.method_calls {
                    if call.name != "require_auth" && call.name != "require_auth_for_args" {
                        continue;
                    }
                    let actor = call.context.trim();
                    if actor.is_empty() {
                        continue;
                    }
                    if first.is_none() {
                        first = Some(call);
                    }
                    actors.insert(actor.to_string());
                }
                if actors.len() < 2 {
                    continue;
                }
                let Some(call) = first else { continue };
                let location = location_for(ctx, source, call.line, call.column);
                let actor_count = actors.len();
                let actors = actors.into_iter().collect::<Vec<_>>().join("`, `");
                let evidence = format!(
                    "entry point `{}` authorizes {actor_count} distinct actors with \
separate `require_auth` calls: `{actors}`",
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
    fn flags_two_distinct_actors() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn move_funds(env: Env, from: Address, to: Address, amount: i128) {
                    from.require_auth();
                    to.require_auth();
                    token(&env).transfer(&from, &to, &amount);
                }
            }
            "#,
            Box::new(CompetingAuthorizationCalls),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-037");
        assert!(findings[0].evidence.contains("distinct actors"));
    }

    #[test]
    fn flags_three_distinct_actors() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn settle(env: Env, a: Address, b: Address, c: Address) {
                    a.require_auth();
                    b.require_auth();
                    c.require_auth();
                }
            }
            "#,
            Box::new(CompetingAuthorizationCalls),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_repeated_auth_for_one_actor() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn settle(env: Env, multisig: Address) {
                    multisig.require_auth();
                    multisig.require_auth_for_args((multisig.clone(),));
                }
            }
            "#,
            Box::new(CompetingAuthorizationCalls),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_a_single_actor() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address) {
                    admin.require_auth();
                }
            }
            "#,
            Box::new(CompetingAuthorizationCalls),
        );
        assert!(findings.is_empty());
    }
}
