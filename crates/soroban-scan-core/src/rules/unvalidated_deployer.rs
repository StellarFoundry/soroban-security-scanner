//! SS-034: unvalidated contract deployer usage without caller authorization.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{
    contract_entry_functions, facts_from_block_with_imports, facts_with_helpers_from_with_imports,
    function_facts_with_imports, location_for, CallFact, Facts,
};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-034",
    title: "Unvalidated deployer usage without caller authorization",
    description: "A public contract entry point uses `env.deployer()` to deploy a \
contract, upload contract WASM, or update the current contract WASM without a \
prior `require_auth` check in its body or in the intra-file helper functions it \
calls. Unvalidated deployment or WASM registration can allow arbitrary callers to \
deploy malicious contracts under the factory's identity, consume deterministic \
salts, or upgrade contract code without authorization.",
    category: Category::Authorization,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Validate and authorize the caller or administrator with \
`admin.require_auth()` (or `require_auth_for_args`) before invoking \
`env.deployer()` deployment or WASM registration methods, and verify the \
deployer identity and resulting address where applicable.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://docs.rs/soroban-sdk/latest/soroban_sdk/deploy/struct.Deployer.html",
    ],
};

/// Terminal methods on `soroban_sdk::deploy::Deployer` / `DeployerWithAddress`
/// that deploy a contract or register/update WASM on-ledger.
const DEPLOYER_ACTION_METHODS: &[&str] = &[
    "deploy",
    "deploy_v2",
    "update_current_contract_wasm",
    "upload_contract_wasm",
];

/// Detects `env.deployer()` chains that deploy or register without prior authorization.
pub struct UnvalidatedDeployer;

impl Rule for UnvalidatedDeployer {
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
                let direct_facts = facts_from_block_with_imports(func.block, &source.imports);
                let facts =
                    facts_with_helpers_from_with_imports(&summaries, &func, &source.imports);

                if !has_deployer_usage(&facts) {
                    continue;
                }

                let helper_has_auth = helper_provides_auth(&direct_facts, &facts);
                let earliest_direct_auth = earliest_auth_byte(&direct_facts);

                for call in deployer_action_calls(&facts) {
                    let authorized_before_call = helper_has_auth
                        || earliest_direct_auth
                            .map(|auth_byte| auth_byte < call.start_byte)
                            .unwrap_or(false);

                    if authorized_before_call {
                        continue;
                    }

                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "unvalidated deployer call without prior authorization in `{}`: {}",
                        func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn has_deployer_usage(facts: &Facts) -> bool {
    facts.method_calls.iter().any(|call| {
        call.name == "deployer"
            || call.name == "with_current_contract"
            || call.name == "with_address"
            || call.name == "update_current_contract_wasm"
            || call.name == "upload_contract_wasm"
    })
}

fn deployer_action_calls(facts: &Facts) -> Vec<&CallFact> {
    facts
        .method_calls
        .iter()
        .filter(|call| {
            if !DEPLOYER_ACTION_METHODS.contains(&call.name.as_str()) {
                return false;
            }
            if call.name == "update_current_contract_wasm" || call.name == "upload_contract_wasm" {
                return true;
            }
            // For `deploy` / `deploy_v2`, confirm the receiver is a deployer chain
            // or the function constructs a deployer instance.
            let recv = call.context.replace(' ', "");
            recv.contains("deployer(")
                || recv.contains("with_current_contract(")
                || recv.contains("with_address(")
                || facts.method_calls.iter().any(|c| c.name == "deployer")
        })
        .collect()
}

fn earliest_auth_byte(facts: &Facts) -> Option<usize> {
    facts
        .method_calls
        .iter()
        .filter(|call| call.name == "require_auth" || call.name == "require_auth_for_args")
        .map(|call| call.start_byte)
        .min()
}

fn helper_provides_auth(direct: &Facts, merged: &Facts) -> bool {
    let direct_auth_count = direct
        .method_calls
        .iter()
        .filter(|call| call.name == "require_auth" || call.name == "require_auth_for_args")
        .count();
    let merged_auth_count = merged
        .method_calls
        .iter()
        .filter(|call| call.name == "require_auth" || call.name == "require_auth_for_args")
        .count();
    merged_auth_count > direct_auth_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_deployer_deploy_without_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(env: Env, salt: BytesN<32>, wasm_hash: BytesN<32>) -> Address {
                    env.deployer().with_current_contract(salt).deploy(wasm_hash)
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-034");
        assert!(findings[0].evidence.contains("create"));
    }

    #[test]
    fn flags_deployer_with_address_and_deploy_v2_without_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn deploy_for(
                    env: Env,
                    deployer: Address,
                    salt: BytesN<32>,
                    wasm_hash: BytesN<32>,
                ) -> Address {
                    env.deployer().with_address(deployer, salt).deploy_v2(wasm_hash, ())
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-034");
    }

    #[test]
    fn flags_wasm_upload_and_update_without_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Upgradable {
                pub fn upgrade(env: Env, wasm: Bytes) {
                    let hash = env.deployer().upload_contract_wasm(wasm);
                    env.deployer().update_current_contract_wasm(hash);
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn flags_deploy_before_require_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(
                    env: Env,
                    admin: Address,
                    salt: BytesN<32>,
                    wasm_hash: BytesN<32>,
                ) -> Address {
                    let addr = env.deployer().with_current_contract(salt).deploy(wasm_hash);
                    admin.require_auth();
                    addr
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-034");
    }

    #[test]
    fn does_not_flag_when_require_auth_precedes_deploy() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(
                    env: Env,
                    admin: Address,
                    salt: BytesN<32>,
                    wasm_hash: BytesN<32>,
                ) -> Address {
                    admin.require_auth();
                    env.deployer().with_current_contract(salt).deploy(wasm_hash)
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_helper_authorizes() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(
                    env: Env,
                    admin: Address,
                    salt: BytesN<32>,
                    wasm_hash: BytesN<32>,
                ) -> Address {
                    Self::check_admin(&admin);
                    env.deployer().with_current_contract(salt).deploy_v2(wasm_hash, ())
                }

                fn check_admin(admin: &Address) {
                    admin.require_auth();
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_deployed_address_read_only_query() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn preview_address(env: Env, salt: BytesN<32>) -> Address {
                    env.deployer().with_current_contract(salt).deployed_address()
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert!(findings.is_empty());
    }
}
