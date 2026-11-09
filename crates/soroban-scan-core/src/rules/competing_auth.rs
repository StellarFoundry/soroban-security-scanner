//! SS-037: competing authorization calls on distinct actors in a single entry point.

use std::collections::BTreeSet;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for, CallFact};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-037",
    title: "Competing authorization calls on distinct actors",
    description: "A single contract entry point invokes `require_auth` or \
`require_auth_for_args` on two or more distinct actor expressions. Requiring \
multiple independent actors to authorize the same entry point often indicates \
confused authorization semantics (for example, requiring both an administrator \
and an unprivileged caller to sign the same state transition) or an accidental \
copy-paste error that can deadlock operations when both signatures are not \
present simultaneously.",
    category: Category::Authorization,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Separate administrative actions from user actions into distinct \
entry points so each operation has a single, unambiguous authorizing actor. \
For legitimate multi-party or multi-sig workflows, either iterate over a \
deduplicated `Vec<Address>` of signers, use a proposal/approval state machine \
across separate invocations, or scope each actor's authorization with \
`require_auth_for_args` and document the multi-party invariant.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security/authorization"],
};

/// Detects entry points that invoke `require_auth` on two or more distinct receivers.
pub struct CompetingAuthCalls;

impl Rule for CompetingAuthCalls {
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
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                let auth_calls: Vec<&CallFact> = facts
                    .method_calls
                    .iter()
                    .filter(|c| c.name == "require_auth" || c.name == "require_auth_for_args")
                    .collect();

                if auth_calls.len() < 2 {
                    continue;
                }

                let mut distinct_actors: Vec<String> = Vec::new();
                let mut seen: BTreeSet<String> = BTreeSet::new();
                let mut second_distinct_call: Option<&CallFact> = None;

                for call in &auth_calls {
                    let normalized = normalize_receiver(&call.context);
                    if normalized.is_empty() {
                        continue;
                    }
                    if seen.insert(normalized.clone()) {
                        if distinct_actors.len() == 1 {
                            second_distinct_call = Some(*call);
                        }
                        distinct_actors.push(normalized);
                    }
                }

                if distinct_actors.len() >= 2 {
                    let report_call = second_distinct_call.unwrap_or(auth_calls[1]);
                    let location = location_for(ctx, source, report_call.line, report_call.column);
                    let actors_list = distinct_actors
                        .iter()
                        .map(|a| format!("`{a}`"))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let evidence = format!(
                        "competing authorization calls on distinct actors ({}) in `{}`: {}",
                        actors_list, func.name, report_call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn normalize_receiver(context: &str) -> String {
    context
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .trim_start_matches('&')
        .trim_start_matches("mut")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_two_distinct_require_auth_receivers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, admin: Address, user: Address, amount: i128) {
                    admin.require_auth();
                    user.require_auth();
                    env.storage().persistent().set(&user, &amount);
                }
            }
            "#,
            Box::new(CompetingAuthCalls),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-037");
        assert!(findings[0].evidence.contains("`admin`, `user`"));
    }

    #[test]
    fn does_not_flag_single_actor_require_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, user: Address, amount: i128) {
                    user.require_auth();
                    env.storage().persistent().set(&user, &amount);
                }
            }
            "#,
            Box::new(CompetingAuthCalls),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_repeated_auth_on_same_actor_or_multisig_signer_slice() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl MultiSigVault {
                pub fn execute_multisig(env: Env, signers: Vec<Address>, payload: BytesN<32>) {
                    for signer in signers.iter() {
                        signer.require_auth_for_args((&payload,).into_val(&env));
                    }
                    env.storage().persistent().set(&payload, &true);
                }
            }
            "#,
            Box::new(CompetingAuthCalls),
        );
        assert!(findings.is_empty());
    }
}
