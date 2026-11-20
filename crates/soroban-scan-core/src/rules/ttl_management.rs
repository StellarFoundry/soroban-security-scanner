//! SS-006: persistent storage write without TTL management.

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
    id: "SS-006",
    title: "Persistent storage write without TTL management",
    description: "A contract entry point writes to persistent storage but does \
not call `extend_ttl`, `set_ttl`, or `bump` in the same function or in the \
intra-file helpers it calls. Persistent \
entries have a time-to-live; if it is not extended, stored data can expire and \
be lost. TTL may legitimately be managed elsewhere (for example in a separate \
maintenance entry point), so this is a low-confidence signal.",
    category: Category::Storage,
    default_severity: Severity::Low,
    default_confidence: Confidence::Low,
    remediation: "When writing persistent data that must survive, extend its \
time-to-live with `storage().persistent().extend_ttl(...)` after the write. \
Prefer a single, well-documented TTL policy for the contract. If TTL is managed \
centrally, suppress this rule for the function.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data"],
    deprecated: false,
};

/// Detects persistent writes without TTL management in the same entry point.
pub struct TtlManagement;

impl Rule for TtlManagement {
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
                let writes = facts.persistent_mutations();
                if writes.is_empty() || !facts.ttl_management().is_empty() {
                    continue;
                }
                for write in writes {
                    let location = location_for(ctx, source, write.line, write.column);
                    let evidence = format!(
                        "persistent storage write without TTL extension in `{}`: {}",
                        func.name, write.text
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
    fn flags_persistent_write_without_ttl() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn put(env: Env, admin: Address, v: u32) {
                    admin.require_auth();
                    env.storage().persistent().set(&K, &v);
                }
            }
            "#,
            Box::new(TtlManagement),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-006");
    }

    #[test]
    fn does_not_flag_when_ttl_extended() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn put(env: Env, admin: Address, v: u32) {
                    admin.require_auth();
                    env.storage().persistent().set(&K, &v);
                    env.storage().persistent().extend_ttl(&K, 100, 1000);
                }
            }
            "#,
            Box::new(TtlManagement),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_helper_extends_ttl() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn put(env: Env, admin: Address, v: u32) {
                    admin.require_auth();
                    env.storage().persistent().set(&K, &v);
                    Self::bump(&env);
                }
                fn bump(env: &Env) {
                    env.storage().persistent().extend_ttl(&K, 100, 1000);
                }
            }
            "#,
            Box::new(TtlManagement),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_instance_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn put(env: Env, v: u32) {
                    env.storage().instance().set(&K, &v);
                }
            }
            "#,
            Box::new(TtlManagement),
        );
        assert!(findings.is_empty());
    }
}
