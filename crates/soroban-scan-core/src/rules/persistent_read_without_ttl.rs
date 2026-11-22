//! SS-039: persistent storage read without TTL management.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, CallFact};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-039",
    title: "Persistent storage read without TTL management",
    description: "A contract entry point reads persistent storage but does not \
call `extend_ttl`, `set_ttl`, or `bump` in the same function or in the intra-file \
helpers it calls. Persistent entries expire; if the read assumes the value is \
still present, an expired entry can change the contract's behaviour or block an \
operation that depends on it. The detector reports only when no TTL management \
is visible at all: a TTL call for an unrelated key is treated as ambiguous and \
suppresses the finding.",
    category: Category::Storage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Refresh the entry's time-to-live when reading persistent data \
that must remain available, for example \
`env.storage().persistent().extend_ttl(&key, threshold, extend_to)` after the \
read. Prefer one documented TTL policy per contract. If TTL is managed by a \
separate maintenance entry point, suppress this rule for the reader with a \
justification.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data"],
};

/// Detects persistent reads without TTL management in the same entry point.
pub struct PersistentReadWithoutTtl;

const READ_METHODS: &[&str] = &["get", "get_unchecked"];

fn is_persistent_read(call: &&CallFact) -> bool {
    READ_METHODS.contains(&call.name.as_str())
        && call.context.to_ascii_lowercase().contains("persistent")
        && call.context.to_ascii_lowercase().contains("storage")
}

impl Rule for PersistentReadWithoutTtl {
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
                let reads: Vec<_> = facts
                    .method_calls
                    .iter()
                    .filter(is_persistent_read)
                    .collect();
                if reads.is_empty() || !facts.ttl_management().is_empty() {
                    continue;
                }
                for read in reads {
                    let location = location_for(ctx, source, read.line, read.column);
                    let evidence = format!(
                        "persistent storage read without TTL extension in `{}`: {}",
                        func.name, read.text
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
    fn flags_persistent_read_without_ttl() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn load(env: Env) -> u32 {
                    env.storage().persistent().get(&K).unwrap()
                }
            }
            "#,
            Box::new(PersistentReadWithoutTtl),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-039");
        assert!(findings[0].evidence.contains("persistent storage read"));
    }

    #[test]
    fn does_not_flag_when_ttl_is_extended() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn load(env: Env) -> u32 {
                    let value = env.storage().persistent().get(&K).unwrap();
                    env.storage().persistent().extend_ttl(&K, 100, 1000);
                    value
                }
            }
            "#,
            Box::new(PersistentReadWithoutTtl),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_instance_or_temporary_reads() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn load(env: Env) -> u32 {
                    let a = env.storage().instance().get(&K).unwrap();
                    let b = env.storage().temporary().get(&K).unwrap();
                    a + b
                }
            }
            "#,
            Box::new(PersistentReadWithoutTtl),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_when_a_helper_extends_ttl() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn load(env: Env) -> u32 {
                    let value = env.storage().persistent().get(&K).unwrap();
                    Self::bump(&env);
                    value
                }
                fn bump(env: &Env) {
                    env.storage().persistent().extend_ttl(&K, 100, 1000);
                }
            }
            "#,
            Box::new(PersistentReadWithoutTtl),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn ignores_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn load(env: Env) -> u32 {
                    env.storage().persistent().get(&K).unwrap()
                }
            }
            "#,
            Box::new(PersistentReadWithoutTtl),
        );
        assert!(findings.is_empty());
    }
}
