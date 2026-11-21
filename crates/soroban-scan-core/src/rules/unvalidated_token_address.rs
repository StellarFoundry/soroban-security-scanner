//! SS-030: a token client is built from an unvalidated caller address.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for, Facts};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-030",
    title: "Token client built from an unvalidated caller address",
    description: "A `token::Client` is constructed from a caller-supplied \
address without comparing it to configuration stored by the contract. An \
attacker can substitute a malicious token contract and change balances or \
transfer semantics. The detector looks for a storage read and comparison that \
guards the construction.",
    category: Category::Token,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Compare the supplied token address with the address stored \
when the contract was configured, and reject mismatches with a typed error before \
constructing the client.",
    references: &[
        "https://developers.stellar.org/docs/tokens/token-interface",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects token clients built from unvalidated parameter addresses.
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
                if !func.is_public {
                    continue;
                }
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                for call in &facts.function_calls {
                    if call.name != "new" || !is_token_client(&call.context) {
                        continue;
                    }
                    let Some(address) = call.args.last() else {
                        continue;
                    };
                    let Some(param) = func
                        .params
                        .iter()
                        .find(|param| contains_ident(address, param))
                    else {
                        continue;
                    };
                    if has_address_check(&facts, param, call.line, call.column) {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "token client constructed from caller-supplied address `{param}` \
                         without a stored-configuration check in `{}`: {}",
                        func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn is_token_client(context: &str) -> bool {
    let lowered = context.to_ascii_lowercase();
    lowered.contains("token") && lowered.contains("client")
}

/// Whether a storage read and a comparison involving `param` precede the call.
fn has_address_check(facts: &Facts, param: &str, line: usize, column: usize) -> bool {
    let reads_storage = facts
        .method_calls
        .iter()
        .any(|call| call.name == "get" && call.context.to_ascii_lowercase().contains("storage"));
    reads_storage
        && facts.comparisons.iter().any(|comparison| {
            (comparison.line, comparison.column) < (line, column)
                && contains_ident(&comparison.text, param)
        })
}

/// Whether `needle` appears in `haystack` as a whole identifier.
fn contains_ident(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(needle) {
        let index = start + offset;
        let end = index + needle.len();
        let before = index == 0 || !is_ident_byte(bytes[index - 1]);
        let after = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before && after {
            return true;
        }
        start = end;
    }
    false
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_token_client_from_parameter() {
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
            Box::new(UnvalidatedTokenAddress),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-030");
        assert!(findings[0].evidence.contains("token_id"));
    }

    #[test]
    fn does_not_flag_when_compared_to_stored_configuration() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
                    let configured: Address = env.storage().persistent().get(&Key::Token).unwrap();
                    if token_id != configured {
                        panic!("unexpected token");
                    }
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &to, &amount);
                }
            }
            "#,
            Box::new(UnvalidatedTokenAddress),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_a_stored_token_address() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, to: Address, amount: i128) {
                    let token: Address = env.storage().persistent().get(&Key::Token).unwrap();
                    let client = token::Client::new(&env, &token);
                    client.transfer(&env.current_contract_address(), &to, &amount);
                }
            }
            "#,
            Box::new(UnvalidatedTokenAddress),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                fn payout(env: Env, token_id: Address) {
                    let client = token::Client::new(&env, &token_id);
                    client.balance(&token_id);
                }
            }
            "#,
            Box::new(UnvalidatedTokenAddress),
        );
        assert!(findings.is_empty());
    }
}
