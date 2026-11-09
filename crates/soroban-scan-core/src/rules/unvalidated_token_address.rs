//! SS-030: token client constructed from an unvalidated `Address` parameter.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-030",
    title: "Token client constructed from unvalidated Address parameter",
    description: "A state-changing contract entry point constructs a token \
client (`token::Client::new` or `TokenClient::new`) from a caller-supplied \
`Address` parameter without comparing it against a stored token address or \
allowlist. An attacker can pass a malicious or worthless token contract to \
credit real protocol balances or hijack execution via a fake token.",
    category: Category::Token,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Load the accepted token contract `Address` from contract \
storage (or verify membership in an allowlist) before constructing \
`token::Client::new` in state-changing entry points.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security"],
};

/// Detects token clients built from unvalidated `Address` parameters in state-changing entry points.
pub struct UnvalidatedTokenAddress;

impl Rule for UnvalidatedTokenAddress {
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
                if !func.is_public || func.params.is_empty() {
                    continue;
                }
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                if facts.storage_mutations().is_empty() {
                    continue;
                }
                for ctor in facts.cross_contract_constructors() {
                    if !ctor.context.to_ascii_lowercase().contains("token") {
                        continue;
                    }
                    let Some(addr_arg) = ctor.argument(1) else {
                        continue;
                    };
                    let Some(param) = func.params.iter().find(|p| {
                        p.as_str() != "env"
                            && addr_arg
                                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                                .any(|tok| tok == p.as_str())
                    }) else {
                        continue;
                    };
                    let validated_by_comparison = facts
                        .comparisons
                        .iter()
                        .any(|cmp| cmp.text.contains(param.as_str()));
                    let validated_by_storage_lookup = facts.method_calls.iter().any(|m| {
                        (m.name == "has" || m.name == "get" || m.name == "contains")
                            && m.args.iter().any(|a| a.contains(param.as_str()))
                    });
                    if validated_by_comparison || validated_by_storage_lookup {
                        continue;
                    }
                    let location = location_for(ctx, source, ctor.line, ctor.column);
                    let evidence = format!(
                        "token client constructed from unvalidated parameter `{}` in `{}`: {}",
                        param, func.name, ctor.text
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
    fn flags_unvalidated_token_parameter_in_deposit() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn deposit(env: Env, user: Address, token: Address, amount: i128) {
                    user.require_auth();
                    let client = token::Client::new(&env, &token);
                    client.transfer(&user, &env.current_contract_address(), &amount);
                    env.storage().persistent().set(&user, &amount);
                }
            }
            "#,
            Box::new(UnvalidatedTokenAddress),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-030");
    }

    #[test]
    fn does_not_flag_when_token_is_verified_against_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn deposit(env: Env, user: Address, token: Address, amount: i128) {
                    user.require_auth();
                    let allowed: Address = env.storage().instance().get(&DataKey::Token).unwrap();
                    if token != allowed {
                        return;
                    }
                    let client = token::Client::new(&env, &token);
                    client.transfer(&user, &env.current_contract_address(), &amount);
                    env.storage().persistent().set(&user, &amount);
                }
            }
            "#,
            Box::new(UnvalidatedTokenAddress),
        );
        assert!(findings.is_empty());
    }
}
