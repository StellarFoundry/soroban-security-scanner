//! SS-002: cross-contract call from an entry point without caller authorization.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{
    contract_entry_functions, facts_with_helpers_from_with_imports, function_facts_with_imports,
    location_for,
};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-002",
    title: "Cross-contract call without caller authorization",
    description: "A public contract function constructs and calls another \
contract client but does not call require_auth in its body or in the intra-file \
helper functions it calls. If the \
contract acts on funds or privileges it controls, an attacker may be able to \
trigger cross-contract effects without the caller's approval. This is a \
heuristic: the called contract may itself enforce authorization, or the \
invocation may be intentionally permissionless.",
    category: Category::CrossContract,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Authorize the caller with `address.require_auth()` before \
invoking another contract on the contract's behalf, and bind the approval to the \
specific arguments of the operation. Verify that any address used to construct \
the client is the expected contract.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security/authorization"],
    deprecated: false,
};

/// Detects unauthenticated cross-contract calls from entry points.
pub struct CrossContractAuth;

impl Rule for CrossContractAuth {
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
            let summaries = function_facts_with_imports(file, &source.imports);
            for func in contract_entry_functions(file) {
                if !func.is_public {
                    continue;
                }
                let facts =
                    facts_with_helpers_from_with_imports(&summaries, &func, &source.imports);
                if facts.has_require_auth() {
                    continue;
                }
                for call in facts.cross_contract_constructors() {
                    if has_trusted_client_address(&facts, call) {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "cross-contract client constructed with no authorization in `{}`: {}",
                        func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

/// True when the client address is trusted configuration rather than an
/// untrusted parameter.
///
/// Constructors take the environment first and the contract address second.
/// A string literal, a storage read, or the current contract address is treated
/// as trusted; any other expression (including a function parameter) is not.
fn has_trusted_client_address(facts: &super::util::Facts, call: &super::util::CallFact) -> bool {
    let Some(address) = call.args.get(1) else {
        return false;
    };
    let lower = address.to_ascii_lowercase();
    if address.contains('"')
        || (lower.contains("storage") && lower.contains("get"))
        || lower.contains("current_contract_address")
    {
        return true;
    }
    let variable = address.trim().trim_start_matches('&').trim();
    facts.storage_vars.contains(variable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_cross_contract_call_without_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn pay(env: Env, id: Address, amount: i128) {
                    let client = TokenClient::new(&env, &id);
                    client.transfer(&env.current_contract_address(), &id, &amount);
                }
            }
            "#,
            Box::new(CrossContractAuth),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-002");
    }

    #[test]
    fn does_not_flag_with_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn pay(env: Env, from: Address, id: Address, amount: i128) {
                    from.require_auth();
                    let client = TokenClient::new(&env, &id);
                    client.transfer(&from, &id, &amount);
                }
            }
            "#,
            Box::new(CrossContractAuth),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_helper_authorizes() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn pay(env: Env, from: Address, id: Address, amount: i128) {
                    Self::authorize(&env, &from);
                    let client = TokenClient::new(&env, &id);
                    client.transfer(&from, &id, &amount);
                }
                fn authorize(_env: &Env, from: &Address) { from.require_auth(); }
            }
            "#,
            Box::new(CrossContractAuth),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_hardcoded_trusted_address() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn pay(env: Env, amount: i128) {
                    let client = TokenClient::new(&env, "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM");
                    client.transfer(&env.current_contract_address(), &amount);
                }
            }
            "#,
            Box::new(CrossContractAuth),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_storage_configured_address() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn pay(env: Env, amount: i128) {
                    let token = env.storage().persistent().get(&DataKey::Token).unwrap();
                    let client = TokenClient::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &amount);
                }
            }
            "#,
            Box::new(CrossContractAuth),
        );
        assert!(findings.is_empty());
    }
}
