//! SS-028: cross-contract call before a state mutation without a guard.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, Facts};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-028",
    title: "Cross-contract call without a reentrancy guard",
    description: "A public entry point makes a cross-contract call and then \
mutates storage without a visible reentrancy guard. Soroban permits reentrancy, \
so a malicious callee can re-enter while state is inconsistent. The detector \
recognizes a documented guard pattern: a storage flag with a lock/guard-style key \
is read and set before the call.",
    category: Category::CrossContract,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Before the external call, read a lock flag from storage, reject \
when it is already set, and set it; clear it after the state update. Or follow \
checks-effects-interactions and update all state before calling out.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
        "https://developers.stellar.org/docs",
    ],
};

/// Detects unguarded cross-contract calls before state mutation.
pub struct MissingReentrancyGuard;

const GUARD_KEY_HINTS: &[&str] = &["lock", "guard", "entered", "reentr", "busy"];

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
                let facts = ctx.facts_for_function(source, &func);
                let mutations = facts.storage_mutations();
                for call in facts.ordered_cross_contract_calls() {
                    let Some(mutation) = mutations
                        .iter()
                        .filter(|mutation| mutation.start_byte > call.start_byte)
                        .min_by_key(|mutation| mutation.start_byte)
                    else {
                        continue;
                    };
                    if has_guard(&facts, call.start_byte) {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "cross-contract call in `{}` at line {} precedes storage mutation \
                         `{}` at line {} with no reentrancy guard: {}",
                        func.name, call.line, mutation.name, mutation.line, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

/// Whether a storage lock flag is read and set before `position`.
fn has_guard(facts: &Facts, position: usize) -> bool {
    let reads_flag = facts.method_calls.iter().any(|call| {
        call.name == "get"
            && call.start_byte < position
            && call.context.to_ascii_lowercase().contains("storage")
    });
    let sets_flag = facts.method_calls.iter().any(|call| {
        call.name == "set"
            && call.start_byte < position
            && call.context.to_ascii_lowercase().contains("storage")
            && call
                .args
                .first()
                .is_some_and(|key| looks_like_guard_key(key))
    });
    reads_flag && sets_flag
}

fn looks_like_guard_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    GUARD_KEY_HINTS.iter().any(|hint| lowered.contains(hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_unguarded_call_before_state_update() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, token: Address, amount: i128) {
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &token, &amount);
                    env.storage().persistent().set(&Key::Balance, &amount);
                }
            }
            "#,
            Box::new(MissingReentrancyGuard),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-028");
    }

    #[test]
    fn does_not_flag_with_a_storage_guard() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, token: Address, amount: i128) {
                    let locked: bool = env.storage().persistent().get(&Key::Locked).unwrap_or(false);
                    if locked {
                        panic!("reentrant");
                    }
                    env.storage().persistent().set(&Key::Locked, &true);
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &token, &amount);
                    env.storage().persistent().set(&Key::Balance, &amount);
                }
            }
            "#,
            Box::new(MissingReentrancyGuard),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_call_after_state_update() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, token: Address, amount: i128) {
                    env.storage().persistent().set(&Key::Balance, &amount);
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &token, &amount);
                }
            }
            "#,
            Box::new(MissingReentrancyGuard),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                fn withdraw(env: Env, token: Address, amount: i128) {
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &token, &amount);
                    env.storage().persistent().set(&Key::Balance, &amount);
                }
            }
            "#,
            Box::new(MissingReentrancyGuard),
        );
        assert!(findings.is_empty());
    }
}
