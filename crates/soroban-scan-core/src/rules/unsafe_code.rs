//! SS-005: `unsafe` code in a Soroban contract.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::location_for;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-005",
    title: "Unsafe code in a Soroban contract",
    description: "The contract source contains an `unsafe` block or expression. \
Soroban contracts execute in a sandbox and rarely require `unsafe`; when it is \
present it bypasses the guarantees Rust normally provides and can undermine \
memory safety assumptions or introduce undefined behavior. This finding is \
evidence of `unsafe` usage, not proof of a bug.",
    category: Category::Unsafe,
    default_severity: Severity::Medium,
    default_confidence: Confidence::High,
    remediation: "Remove the `unsafe` block if possible. If it is genuinely \
required, isolate it in a small, well-documented function, prove its invariants, \
and cover it with targeted tests. Document why safe alternatives are \
insufficient.",
    references: &[
        "https://doc.rust-lang.org/nomicon/",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects `unsafe` blocks in contract source files.
pub struct UnsafeCode;

impl Rule for UnsafeCode {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        for source in ctx.sources() {
            if source.syntax.is_none() {
                continue;
            }
            let facts = ctx.facts_for_source(source);
            for (line, column) in &facts.unsafe_locations {
                let location = location_for(ctx, source, *line, *column);
                let evidence = format!("unsafe block/expression in {}", source.path.display());
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
    fn flags_unsafe_block() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn f(p: *const u8) {
                    unsafe { std::ptr::read(p); }
                }
            }
            "#,
            Box::new(UnsafeCode),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-005");
    }

    #[test]
    fn does_not_flag_safe_code() {
        let findings = scan_rule(
            "#[contractimpl]\nimpl C { pub fn f(x: u32) -> u32 { x + 1 } }\n",
            Box::new(UnsafeCode),
        );
        assert!(findings.is_empty());
    }
}
