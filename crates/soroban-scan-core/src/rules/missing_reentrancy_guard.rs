//! SS-028: state mutation after a cross-contract call without a reentrancy guard.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Identifiers that indicate an explicit reentrancy lock/guard.
pub const REENTRANCY_GUARD_HINTS: &[&str] = &[
    "lock",
    "reentrancy",
    "reentrant",
    "entered",
    "guard",
    "in_progress",
    "mutex",
];

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-028",
    title: "State mutation after cross-contract call without reentrancy guard",
    description: "A public contract entry point mutates contract state (`set`, \
`update`, or `remove`) after an external cross-contract invocation without \
acquiring a reentrancy lock. If the remote contract re-enters before the \
post-call write completes, it can observe or corrupt intermediate state.",
    category: Category::CrossContract,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Apply all state mutations before invoking external contracts \
(checks-effects-interactions), or protect the entry point with an explicit \
reentrancy guard stored in temporary/instance storage.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security"],
};

/// Detects post-call state writes when no reentrancy guard is present.
pub struct MissingReentrancyGuard;

fn has_reentrancy_guard(block_text: &str) -> bool {
    let lower = block_text.to_ascii_lowercase();
    REENTRANCY_GUARD_HINTS
        .iter()
        .any(|hint| lower.contains(hint))
}

impl Rule for MissingReentrancyGuard {
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
                let calls = facts.ordered_cross_contract_calls();
                let Some(earliest_call) = calls.first() else {
                    continue;
                };
                let all_text: String = facts
                    .method_calls
                    .iter()
                    .chain(facts.function_calls.iter())
                    .map(|c| c.text.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                if has_reentrancy_guard(&all_text) {
                    continue;
                }
                for write in facts.storage_mutations() {
                    if !matches!(write.name.as_str(), "set" | "update" | "remove") {
                        continue;
                    }
                    if write.start_byte <= earliest_call.start_byte {
                        continue;
                    }
                    let location = location_for(ctx, source, write.line, write.column);
                    let evidence = format!(
                        "storage `{}` in `{}` occurs after cross-contract call `{}` without a reentrancy guard",
                        write.name, func.name, earliest_call.name
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
    fn flags_post_call_write_without_guard() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Pool {
                pub fn claim(env: Env, user: Address, token: Address, amount: i128) {
                    user.require_auth();
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &user, &amount);
                    env.storage().persistent().set(&user, &0_i128);
                }
            }
            "#,
            Box::new(MissingReentrancyGuard),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-028");
    }

    #[test]
    fn does_not_flag_when_reentrancy_guard_present() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Pool {
                pub fn claim(env: Env, user: Address, token: Address, amount: i128) {
                    user.require_auth();
                    env.storage().temporary().set(&symbol_short!("LOCK"), &true);
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &user, &amount);
                    env.storage().persistent().set(&user, &0_i128);
                }
            }
            "#,
            Box::new(MissingReentrancyGuard),
        );
        assert!(findings.is_empty());
    }
}
