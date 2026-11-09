//! SS-013: cross-contract call before the first state update.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-013",
    title: "Cross-contract call before state update",
    description: "A public contract entry point makes a cross-contract call \
before its first storage write. Soroban permits reentrancy, so a malicious \
callee can be invoked while the caller's state still reflects the pre-call \
values and may re-enter or observe inconsistent state. This is a heuristic \
ordering check: it only compares call and mutation positions within the same \
function and cannot prove that reentrancy is reachable or exploitable.",
    category: Category::CrossContract,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Follow checks-effects-interactions: validate inputs, update all \
relevant contract state, and only then invoke another contract. If an external \
call must happen first, add an explicit reentrancy guard and document why the \
intermediate state is safe to observe.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
        "https://developers.stellar.org/docs",
    ],
    deprecated: false,
};

/// Detects cross-contract calls that precede the first storage mutation.
pub struct CrossContractBeforeStateUpdate;

impl Rule for CrossContractBeforeStateUpdate {
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
                let Some(first_write) = facts
                    .storage_mutations()
                    .into_iter()
                    .min_by_key(|mutation| mutation.start_byte)
                else {
                    continue;
                };

                for call in facts.ordered_cross_contract_calls() {
                    if call.start_byte >= first_write.start_byte {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "cross-contract call in `{}` at line {} (byte {}) precedes the first storage write `{}` at line {} (byte {})",
                        func.name,
                        call.line,
                        call.start_byte,
                        first_write.name,
                        first_write.line,
                        first_write.start_byte
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
    fn flags_call_before_state_update() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, to: Address, amount: i128) {
                    let client = TokenClient::new(&env, &to);
                    client.transfer(&env.current_contract_address(), &to, &amount);
                    env.storage().persistent().set(&Key::Pending, &amount);
                }
            }
            "#,
            Box::new(CrossContractBeforeStateUpdate),
        );
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert_eq!(findings[0].rule_id, "SS-013");
        assert!(findings[0].evidence.contains("precedes"));
        assert!(findings[0].evidence.contains("byte"));
    }

    #[test]
    fn does_not_flag_call_after_state_update() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn withdraw(env: Env, to: Address, amount: i128) {
                    env.storage().persistent().set(&Key::Pending, &amount);
                    let client = TokenClient::new(&env, &to);
                    client.transfer(&env.current_contract_address(), &to, &amount);
                }
            }
            "#,
            Box::new(CrossContractBeforeStateUpdate),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_read_only_cross_contract_call() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn balance(env: Env, id: Address) -> i128 {
                    let client = TokenClient::new(&env, &id);
                    client.balance(&id)
                }
            }
            "#,
            Box::new(CrossContractBeforeStateUpdate),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_the_constructor_when_no_client_call_is_resolved() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn touch(env: Env, id: Address) {
                    TokenClient::new(&env, &id);
                    env.storage().persistent().set(&Key::Seen, &true);
                }
            }
            "#,
            Box::new(CrossContractBeforeStateUpdate),
        );
        assert_eq!(findings.len(), 1, "got: {findings:#?}");
        assert!(findings[0].evidence.contains("precedes"));
    }
}
