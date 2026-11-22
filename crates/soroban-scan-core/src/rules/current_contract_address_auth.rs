//! SS-027: `current_contract_address` used as an authorization subject.
//!
//! `env.current_contract_address().require_auth()` authorizes the contract
//! itself rather than the caller. It is almost always a logic error that defeats
//! the intended access control.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-027",
    title: "Contract's own address used as an authorization subject",
    description: "Passing `env.current_contract_address()` to `require_auth` \
authorizes the contract itself instead of the caller. This is almost always a \
logic error: the check succeeds for anyone who can invoke the contract, so it \
does not provide the intended access control.",
    category: Category::Authorization,
    default_severity: Severity::High,
    default_confidence: Confidence::Medium,
    remediation: "Authorize the actual caller instead: take an `Address` \
parameter and call `caller.require_auth()`, or call `require_auth` on the stored \
owner/admin address. Reserve `current_contract_address()` for checks that really \
concern this contract's identity.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects `current_contract_address()` passed to `require_auth`.
pub struct CurrentContractAddressAuth;

impl Rule for CurrentContractAddressAuth {
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
                for call in &facts.method_calls {
                    if !is_require_auth(&call.name)
                        || !mentions_current_contract_address(&call.context)
                    {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "`{}` authorizes the contract's own address instead of the caller \
                         in `{}`: {}",
                        call.name, func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
                // Also catch the UFCS form if it ever appears.
                for call in &facts.function_calls {
                    if !is_require_auth(&call.name)
                        || !mentions_current_contract_address(&call.context)
                    {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "`{}` authorizes the contract's own address instead of the caller \
                         in `{}`: {}",
                        call.name, func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn is_require_auth(name: &str) -> bool {
    name == "require_auth" || name == "require_auth_for_args"
}

fn mentions_current_contract_address(context: &str) -> bool {
    context
        .to_ascii_lowercase()
        .contains("current_contract_address")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_current_contract_address_require_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn guarded(env: Env) {
                    env.current_contract_address().require_auth();
                }
            }
            "#,
            Box::new(CurrentContractAddressAuth),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-027");
    }

    #[test]
    fn flags_require_auth_for_args_on_contract_address() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn guarded(env: Env, amount: i128) {
                    env.current_contract_address().require_auth_for_args((amount,));
                }
            }
            "#,
            Box::new(CurrentContractAddressAuth),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_caller_authorization() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn guarded(env: Env, admin: Address) {
                    admin.require_auth();
                }
            }
            "#,
            Box::new(CurrentContractAddressAuth),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_contract_address_used_for_identity() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn id(env: Env) -> Address {
                    env.current_contract_address()
                }
            }
            "#,
            Box::new(CurrentContractAddressAuth),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn guarded(env: Env) {
                    env.current_contract_address().require_auth();
                }
            }
            "#,
            Box::new(CurrentContractAddressAuth),
        );
        assert!(findings.is_empty());
    }
}
