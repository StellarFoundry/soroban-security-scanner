//! SS-012: unbounded collection growth in an entry point.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

const GROWTH_METHODS: &[&str] = &["push", "push_back", "push_front"];

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-012",
    title: "Unbounded collection growth in an entry point",
    description: "A contract entry point grows a collection that was read from \
storage without checking a length or capacity limit. Repeated calls can grow the \
ledger entry without bound, increasing rent and eventually making reads or \
iteration fail, a denial of service.",
    category: Category::ResourceUsage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Cap the collection size before growing it: read the current \
length and reject the operation at a documented maximum, or store a bounded \
aggregate instead. Return a typed contract error when the cap is reached.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/resource-limits",
    ],
    deprecated: false,
};

/// Detects unbounded collection growth inside contract entry points.
pub struct UnboundedVecGrowth;

impl Rule for UnboundedVecGrowth {
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
                if facts.storage_mutations().is_empty() || has_length_guard(&facts) {
                    continue;
                }
                let reads_storage = facts.method_calls.iter().any(|call| {
                    call.name == "get" && call.context.to_ascii_lowercase().contains("storage")
                });
                if !reads_storage {
                    continue;
                }
                for growth in facts
                    .method_calls
                    .iter()
                    .filter(|call| GROWTH_METHODS.contains(&call.name.as_str()))
                {
                    let location = location_for(ctx, source, growth.line, growth.column);
                    let evidence = format!(
                        "unbounded collection growth in `{}`: {}",
                        func.name, growth.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn has_length_guard(facts: &super::util::Facts) -> bool {
    facts.method_calls.iter().any(|call| call.name == "len")
        || facts
            .comparisons
            .iter()
            .any(|comparison| comparison.text.contains("len()"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_unbounded_push_after_storage_read() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn add(env: Env, item: u32) {
                    let mut items: Vec<u32> = env
                        .storage()
                        .persistent()
                        .get(&DataKey::Items)
                        .unwrap_or(Vec::new(&env));
                    items.push_back(item);
                    env.storage().persistent().set(&DataKey::Items, &items);
                }
            }
            "#,
            Box::new(UnboundedVecGrowth),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-012");
        assert!(findings[0].evidence.contains("unbounded collection growth"));
    }

    #[test]
    fn does_not_flag_a_capped_collection() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn add(env: Env, item: u32) {
                    let mut items: Vec<u32> = env
                        .storage()
                        .persistent()
                        .get(&DataKey::Items)
                        .unwrap_or(Vec::new(&env));
                    if items.len() >= 100 {
                        panic!("cap reached");
                    }
                    items.push_back(item);
                    env.storage().persistent().set(&DataKey::Items, &items);
                }
            }
            "#,
            Box::new(UnboundedVecGrowth),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_a_local_collection() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn build(env: Env) -> Vec<u32> {
                    let mut items = Vec::new(&env);
                    items.push_back(1);
                    items
                }
            }
            "#,
            Box::new(UnboundedVecGrowth),
        );
        assert!(findings.is_empty());
    }
}
