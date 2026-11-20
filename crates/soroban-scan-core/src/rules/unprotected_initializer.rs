//! SS-011: initialization entry point without a re-initialization guard.

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
    id: "SS-011",
    title: "Initialization entry point without a re-initialization guard",
    description: "An initialization-style entry point (for example `initialize` \
or `init`) writes contract storage without first checking whether the contract \
has already been initialized. If the function stays callable after deployment, \
anyone can call it again to overwrite configuration or take over privileged \
state. This is a heuristic based on the function name and the absence of an \
authorization check or a storage existence read in the function or its \
same-file helpers.",
    category: Category::AccessControl,
    default_severity: Severity::High,
    default_confidence: Confidence::Low,
    remediation: "Guard initialization by checking that the contract is not \
already initialized before writing (for example \
`if env.storage().instance().has(&KEY) { return Err(Error::AlreadyInitialized) }`), \
or perform initialization in a constructor (`__constructor`) so it runs only at \
deploy time.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security"],
    deprecated: false,
};

/// Detects initialization entry points that lack a re-initialization guard.
pub struct UnprotectedInitializer;

/// Name segments that indicate an initialization entry point.
const INIT_SEGMENTS: &[&str] = &["initialize", "initialise", "init", "setup", "configure"];

fn is_initializer(name: &str) -> bool {
    name.to_ascii_lowercase()
        .split('_')
        .any(|segment| INIT_SEGMENTS.contains(&segment))
}

impl Rule for UnprotectedInitializer {
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
                if !func.is_public || !is_initializer(&func.name) {
                    continue;
                }
                let facts =
                    facts_with_helpers_from_with_imports(&summaries, &func, &source.imports);
                // Authorization or an existence read indicates a guard.
                if facts.has_require_auth() {
                    continue;
                }
                let writes = facts.storage_mutations();
                if writes.is_empty() {
                    continue;
                }
                let guarded = facts
                    .method_calls
                    .iter()
                    .any(|call| call.name == "has" || call.name == "get");
                if guarded {
                    continue;
                }
                for write in writes {
                    let location = location_for(ctx, source, write.line, write.column);
                    let evidence = format!(
                        "initializer `{}` writes storage without a re-initialization guard: {}",
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
    fn flags_unprotected_initialize() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn initialize(env: Env, admin: Address) {
                    env.storage().persistent().set(&ADMIN, &admin);
                }
            }
            "#,
            Box::new(UnprotectedInitializer),
        );
        assert_eq!(findings[0].rule_id, "SS-011");
        assert!(findings[0].evidence.contains("initialize"));
    }

    #[test]
    fn does_not_flag_when_guard_reads_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn initialize(env: Env, admin: Address) {
                    if env.storage().instance().has(&ADMIN) {
                        return;
                    }
                    env.storage().persistent().set(&ADMIN, &admin);
                }
            }
            "#,
            Box::new(UnprotectedInitializer),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_authorized() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn initialize(env: Env, admin: Address) {
                    admin.require_auth();
                    env.storage().persistent().set(&ADMIN, &admin);
                }
            }
            "#,
            Box::new(UnprotectedInitializer),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_non_initializer() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_admin(env: Env, a: Address) {
                    env.storage().persistent().set(&ADMIN, &a);
                }
            }
            "#,
            Box::new(UnprotectedInitializer),
        );
        assert!(findings.is_empty());
    }
}
