//! SS-003: unbounded storage iteration in an entry point.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-003",
    title: "Unbounded storage iteration in an entry point",
    description: "A contract entry point iterates over storage. If the iterated \
collection grows without bound, the operation's resource cost grows with it and \
may exceed Soroban's ledger entry, CPU, or memory limits, causing the entry \
point to fail (a denial of service). Soroban does not provide storage \
enumeration in the same way as some platforms, so patterns that loop over \
persistent collections built by the contract are the usual cause.",
    category: Category::ResourceUsage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Bound the amount of work performed per invocation: paginate \
with an explicit limit, maintain aggregate values instead of scanning, or cap \
the number of entries processed and return partial results. Ensure any loop \
over storage is bounded by a value the contract controls.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/resource-limits",
    ],
    deprecated: false,
};

/// Detects storage iteration inside contract entry points.
pub struct UnboundedIteration;

impl Rule for UnboundedIteration {
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
                for iteration in facts.storage_iterations() {
                    let location = location_for(ctx, source, iteration.line, iteration.column);
                    let evidence =
                        format!("storage iteration in `{}`: {}", func.name, iteration.text);
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
    fn flags_storage_iteration() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn total(env: Env) -> u32 {
                    let mut sum = 0;
                    for key in env.storage().persistent().keys() {
                        sum += 1;
                    }
                    sum
                }
            }
            "#,
            Box::new(UnboundedIteration),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-003");
    }

    #[test]
    fn does_not_flag_bounded_local_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn sum(xs: Vec<u32>) -> u32 {
                    let mut sum = 0;
                    for key in xs.iter() {
                        sum += key;
                    }
                    sum
                }
            }
            "#,
            Box::new(UnboundedIteration),
        );
        assert!(findings.is_empty());
    }
}
