//! SS-001: state-changing entry point without caller authorization.

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
    id: "SS-001",
    title: "State-changing entry point without caller authorization",
    description: "A public contract function mutates storage but does not call \
require_auth or require_auth_for_args anywhere in its body or in the intra-file \
helper functions it calls. Without an \
authorization check, any account can invoke the function and change contract \
state, which may allow theft, privilege escalation, or corruption of contract \
data. This is a heuristic: authorization may legitimately be enforced by a \
callee or be intentionally absent for permissionless operations.",
    category: Category::Authorization,
    default_severity: Severity::High,
    default_confidence: Confidence::Medium,
    remediation: "Call `address.require_auth()` (or `require_auth_for_args`) for \
the account that must approve the operation before mutating state. Prefer \
authorizing a specific argument that binds the approval to the operation rather \
than authorizing a stored admin address unconditionally. If the function is \
intentionally permissionless, document that and suppress this rule for the \
function.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security/authorization"],
    deprecated: false,
};

/// Detects storage-mutating entry points without authorization.
pub struct MissingAuthorization;

impl Rule for MissingAuthorization {
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
                for mutation in facts.storage_mutations() {
                    let location = location_for(ctx, source, mutation.line, mutation.column);
                    let evidence = format!(
                        "`{}` storage mutation with no authorization in `{}`: {}",
                        mutation.name, func.name, mutation.text
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
    fn flags_storage_write_without_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_value(env: Env, v: u32) {
                    env.storage().persistent().set(&Key::V, &v);
                }
            }
            "#,
            Box::new(MissingAuthorization),
        );
        assert_eq!(findings[0].rule_id, "SS-001");
        assert!(findings[0].evidence.contains("storage mutation"));
    }

    #[test]
    fn does_not_flag_when_auth_present() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_value(env: Env, admin: Address, v: u32) {
                    admin.require_auth();
                    env.storage().persistent().set(&Key::V, &v);
                }
            }
            "#,
            Box::new(MissingAuthorization),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_helper_authorizes() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_value(env: Env, v: u32) {
                    Self::check_auth(&env);
                    env.storage().persistent().set(&Key::V, &v);
                }
                fn check_auth(env: &Env) {
                    let admin = get_admin(env);
                    admin.require_auth();
                }
            }
            "#,
            Box::new(MissingAuthorization),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_read_only_entry_point() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn get_value(env: Env) -> u32 {
                    env.storage().persistent().get(&Key::V).unwrap_or(0)
                }
            }
            "#,
            Box::new(MissingAuthorization),
        );
        assert!(findings.is_empty());
    }
}
