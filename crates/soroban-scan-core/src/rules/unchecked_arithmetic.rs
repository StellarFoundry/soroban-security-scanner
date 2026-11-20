//! SS-008: unchecked arithmetic in a contract entry point.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-008",
    title: "Unchecked arithmetic in a contract entry point",
    description: "A public contract entry point performs binary arithmetic (`+`, \
`-`, or `*`) on values without a checked, saturating, overflowing, or wrapping \
operation. In release builds Rust arithmetic wraps on overflow and underflow \
instead of panicking, so a decrement below zero (or an overflow) can silently \
produce an incorrect result — a common cause of balance and accounting bugs in \
token, escrow and vault contracts. This is a heuristic: it cannot prove that the \
operands are attacker-influenced or that their range is constrained, so it \
reports low confidence and should be reviewed in context.",
    category: Category::Arithmetic,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Use explicit checked arithmetic (`checked_add`, `checked_sub`, \
`checked_mul`) and handle the `None` case with a typed contract error, or use \
saturating/overflowing variants when that semantics is intended. Prefer checked \
operations for balances, amounts, and counters derived from user input.",
    references: &[
        "https://doc.rust-lang.org/reference/expressions/operator-expr.html#overflow",
        "https://developers.stellar.org/docs",
    ],
    deprecated: false,
};

/// Detects unchecked binary arithmetic inside contract entry points.
pub struct UncheckedArithmetic;

impl Rule for UncheckedArithmetic {
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
                // If the entry point already uses explicit overflow-aware
                // arithmetic anywhere, assume the author is managing it
                // deliberately and stay quiet to avoid false positives.
                if facts.method_calls.iter().any(|c| {
                    let name = c.name.as_str();
                    name.starts_with("checked_")
                        || name.starts_with("saturating_")
                        || name.starts_with("overflowing_")
                        || name.starts_with("wrapping_")
                }) {
                    continue;
                }
                for op in facts.arithmetic_ops() {
                    let location = location_for(ctx, source, op.line, op.column);
                    let suggested = match op.op.as_str() {
                        "+" => "checked_add",
                        "-" => "checked_sub",
                        "*" => "checked_mul",
                        _ => "checked arithmetic",
                    };
                    let evidence = format!(
                        "unchecked `{}` arithmetic in entry point `{}`: {} (use `{}` and handle `None`)",
                        op.op, func.name, op.text, suggested
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
    fn flags_unchecked_subtraction() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn withdraw(env: Env, amount: i128) -> i128 {
                    let balance = 100i128;
                    balance - amount
                }
            }
            "#,
            Box::new(UncheckedArithmetic),
        );
        assert_eq!(findings[0].rule_id, "SS-008");
        assert!(findings[0].evidence.contains("unchecked `-` arithmetic"));
    }

    #[test]
    fn does_not_flag_checked_arithmetic() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn withdraw(env: Env, amount: i128) -> i128 {
                    let balance = 100i128;
                    balance.checked_sub(amount).unwrap_or(0)
                }
            }
            "#,
            Box::new(UncheckedArithmetic),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers_or_read_only_math() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn total(env: Env) -> i128 { helper(1, 2) }
                fn helper(a: i128, b: i128) -> i128 { a - b }
            }
            "#,
            Box::new(UncheckedArithmetic),
        );
        assert!(findings.is_empty());
    }
}
