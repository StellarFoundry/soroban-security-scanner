//! SS-004: panic-prone constructs in a contract entry point.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-004",
    title: "Panic-prone construct in a contract entry point",
    description: "A contract entry point calls `unwrap`, `expect`, `panic!`, \
`todo!`, `unimplemented!`, or `unreachable!`. In Soroban these abort the \
invocation and roll back state. When reachable from normal input, this turns a \
recoverable error condition into a failed transaction (a denial of service). \
This is a code-quality signal rather than proof of a vulnerability.",
    category: Category::ErrorHandling,
    default_severity: Severity::Low,
    default_confidence: Confidence::Medium,
    remediation: "Return a `Result` with a typed contract error instead of \
panicking, so callers can handle failure. Replace `unwrap`/`expect` on \
fallible operations with `?`, `unwrap_or`, `unwrap_or_default`, or explicit \
matching.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/errors-and-fees",
        "https://developers.stellar.org/docs/tools/cli/stellar-cli",
    ],
    deprecated: false,
};

/// Detects panic-prone constructs inside contract entry points.
pub struct PanicProne;

impl Rule for PanicProne {
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
                for (name, line, column, text) in facts.panics() {
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!("`{name}` in `{}` can panic: {text}", func.name);
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
    fn flags_unwrap_and_panic() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn f(env: Env) -> u32 {
                    let v = env.storage().persistent().get(&K).unwrap();
                    if v == 0 { panic!("zero"); }
                    v
                }
            }
            "#,
            Box::new(PanicProne),
        );
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.rule_id == "SS-004"));
    }

    #[test]
    fn does_not_flag_result_based_code() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn f(env: Env) -> u32 {
                    env.storage().persistent().get(&K).unwrap_or(0)
                }
            }
            "#,
            Box::new(PanicProne),
        );
        assert!(findings.is_empty());
    }
}
