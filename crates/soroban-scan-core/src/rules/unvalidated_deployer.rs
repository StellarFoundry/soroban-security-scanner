//! SS-034: contract deployment through `env.deployer()` without authorization.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-034",
    title: "Unvalidated deployer usage",
    description: "A contract entry point uses `env.deployer()` to deploy or \
register a contract without any `require_auth` authorization fact in the \
function or its intra-file helpers. Deploying contracts is a privileged action; \
if it is open to any caller, an attacker can install attacker-controlled code, \
replace a contract, or consume the contract's deployment quota. The detector is \
syntactic and reports low confidence because authorization may be enforced \
elsewhere.",
    category: Category::AccessControl,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Require authorization from the administrator or the address \
that owns the deployment before calling `env.deployer()`, for example \
`admin.require_auth()` after loading a trusted admin address from storage. Bind \
the authorization to the deployed address or salt where possible, and reject \
callers that are not allowed to deploy.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://developers.stellar.org/docs/build/guides/deploying-contracts",
    ],
};

/// Detects deployment through `env.deployer()` without authorization facts.
pub struct UnvalidatedDeployer;

const DEPLOY_METHODS: &[&str] = &[
    "deploy",
    "deploy_v2",
    "upload_contract_wasm",
    "update_current_contract_wasm",
];

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
            for func in contract_entry_functions(file) {
                if !func.is_public {
                    continue;
                }
                let facts = ctx.helper_facts_for_function(source, &func);
                if facts.has_require_auth() {
                    continue;
                }
                let Some(deployer) = facts
                    .method_calls
                    .iter()
                    .find(|call| call.name == "deployer")
                else {
                    continue;
                };
                if !facts
                    .method_calls
                    .iter()
                    .any(|call| DEPLOY_METHODS.contains(&call.name.as_str()))
                {
                    continue;
                }
                let location = location_for(ctx, source, deployer.line, deployer.column);
                let evidence = format!(
                    "`env.deployer()` deployment without authorization in `{}`: {}",
                    func.name, deployer.text
                );
                out.push(Finding::new(&METADATA, location, evidence));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_deploy_without_authorization() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(env: Env, wasm: BytesN<32>, salt: BytesN<32>) -> Address {
                    env.deployer()
                        .with_current_contract(salt)
                        .deploy(wasm)
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-034");
        assert!(findings[0].evidence.contains("deployer"));
    }

    #[test]
    fn does_not_flag_when_authorization_is_present() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(env: Env, admin: Address, wasm: BytesN<32>, salt: BytesN<32>) -> Address {
                    admin.require_auth();
                    env.deployer()
                        .with_current_contract(salt)
                        .deploy(wasm)
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_when_helper_authorizes() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(env: Env, wasm: BytesN<32>, salt: BytesN<32>) -> Address {
                    Self::check(&env);
                    env.deployer()
                        .with_current_contract(salt)
                        .deploy(wasm)
                }
                fn check(env: &Env) {
                    let admin = get_admin(env);
                    admin.require_auth();
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_deployer_without_a_deploy_call() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn address(env: Env) -> Address {
                    let deployer = env.deployer();
                    deployer.current_contract_address()
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_a_client_deploy_call() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Factory {
                pub fn create(env: Env, wasm: BytesN<32>) {
                    let client = FactoryClient::new(&env, &id);
                    client.deploy(&wasm);
                }
            }
            "#,
            Box::new(UnvalidatedDeployer),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }
}
