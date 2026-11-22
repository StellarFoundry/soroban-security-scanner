//! SS-044: cross-contract address argument without validation.

use crate::analysis::taint::{address_argument_flows, is_privileged_address_call, TaintPath};
use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-044",
    title: "Cross-contract call with an unvalidated address argument",
    description: "A cross-contract token call receives an address argument that \
originates from a caller-supplied parameter and was not passed through a documented \
address-validation helper. The scanner cannot prove the address is the expected \
account or contract, so a caller may direct a transfer, approval, mint, or burn at \
an unintended destination. Flows with more than one origin, or validation that \
happens only on some paths, are recorded as ambiguous by the taint analysis and \
are not reported.",
    category: Category::CrossContract,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Validate the address before the cross-contract call. Use a \
documented helper such as `validate_address`, compare against an address stored \
at configuration time, or reject addresses that are not on an explicit allowlist. \
Validate on every path, before the call.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
        "https://developers.stellar.org/docs/tokens/token-interface",
    ],
};

/// Detects caller-controlled addresses passed to privileged token calls.
pub struct UnvalidatedCrossContractAddress;

impl Rule for UnvalidatedCrossContractAddress {
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
                let facts = ctx.helper_facts_for_function(source, &func);
                if !facts
                    .method_calls
                    .iter()
                    .chain(facts.function_calls.iter())
                    .any(|call| is_privileged_address_call(&call.name))
                {
                    continue;
                }
                for flow in address_argument_flows(file, &func) {
                    // More than one tainted origin, or validation that may not
                    // run on every path, is ambiguous. Record nothing.
                    if matches!(flow.path, TaintPath::Unknown { .. }) {
                        continue;
                    }
                    let index = flow.sink.argument.map(|argument| argument + 1).unwrap_or(0);
                    let location =
                        location_for(ctx, source, flow.sink.span.line, flow.sink.span.column);
                    let evidence = format!(
                        "cross-contract `{}` passes caller-controlled address argument {} \
                         from `{}` without documented validation in `{}`",
                        flow.sink.name,
                        index,
                        flow.path.description(),
                        func.name
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
    fn flags_caller_controlled_recipient() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &to, &amount);
                }
            }
            "#,
            Box::new(UnvalidatedCrossContractAddress),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-044");
        assert!(findings[0].evidence.contains("to"));
        assert!(findings[0].evidence.contains("transfer"));
    }

    #[test]
    fn does_not_flag_a_validated_address() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
                    let recipient = validate_address(&env, to);
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &recipient, &amount);
                }
            }
            fn validate_address(env: &Env, candidate: Address) -> Address { candidate }
            "#,
            Box::new(UnvalidatedCrossContractAddress),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_a_storage_derived_address() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, amount: i128) {
                    let treasury: Address = env.storage().instance().get(&0).unwrap();
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &treasury, &amount);
                }
            }
            "#,
            Box::new(UnvalidatedCrossContractAddress),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_conditional_validation_as_ambiguous() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, to: Address, amount: i128, trusted: bool) {
                    let mut recipient = to;
                    if trusted {
                        recipient = validate_address(&env, to);
                    }
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &recipient, &amount);
                }
            }
            fn validate_address(env: &Env, candidate: Address) -> Address { candidate }
            "#,
            Box::new(UnvalidatedCrossContractAddress),
        );
        assert!(
            findings.is_empty(),
            "ambiguous flows must not fire: {findings:#?}"
        );
    }

    #[test]
    fn ignores_private_helpers_and_non_address_calls() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn balance(env: Env, token_id: Address, owner: Address) -> i128 {
                    token::Client::new(&env, &token_id).balance(&owner)
                }
                fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
                    token::Client::new(&env, &token_id).transfer(&env.current_contract_address(), &to, &amount);
                }
            }
            "#,
            Box::new(UnvalidatedCrossContractAddress),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }
}
