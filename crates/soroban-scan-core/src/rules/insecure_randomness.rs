//! SS-009: insecure randomness derived from predictable ledger state.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-009",
    title: "Insecure randomness derived from ledger state",
    description: "A public contract entry point uses the ledger timestamp or \
ledger sequence in arithmetic, modulo, or a comparison that appears to select an \
outcome. Ledger values are publicly known and can be influenced by transaction \
submission timing, so deriving randomness from them is predictable and may let \
an attacker steer lotteries, winner selection, or other value-dependent logic. \
This is a heuristic: it reports low confidence and cannot prove that the value is \
used as randomness or that an attacker can control the result.",
    category: Category::Arithmetic,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Do not derive randomness from `ledger().timestamp()` or \
`ledger().sequence()`. Use a commitment/reveal scheme, a verifiable randomness \
source, or another design that does not depend on ledger values the submitter can \
observe or influence. If the value is only used for an expiry check against a \
stored deadline, document the use and suppress this rule.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
        "https://developers.stellar.org/docs",
    ],
};

/// Detects predictable ledger values used in outcome-selecting expressions.
pub struct InsecureRandomness;

/// A binary expression that contains a ledger accessor.
struct SelectingExpression<'a> {
    line: usize,
    column: usize,
    kind: &'a str,
    text: &'a str,
}

fn mentions_ledger(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("ledger") && (lower.contains("timestamp") || lower.contains("sequence"))
}

/// Returns true when a comparison looks like an ordinary expiry check against a
/// stored or explicitly named deadline rather than an outcome selection.
fn looks_like_deadline(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("storage")
        || [
            "deadline",
            "expiry",
            "expires",
            "expire_at",
            "expiration",
            "due_at",
            "maturity",
            "ttl",
        ]
        .iter()
        .any(|needle| lower.contains(needle))
}

impl Rule for InsecureRandomness {
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

                let facts = ctx.facts_for_function(source, &func);
                let accesses = facts.ledger_accesses();
                if accesses.is_empty() {
                    continue;
                }

                let mut selecting: Vec<SelectingExpression<'_>> = Vec::new();
                selecting.extend(facts.comparisons.iter().filter_map(|fact| {
                    mentions_ledger(&fact.text).then_some(SelectingExpression {
                        line: fact.line,
                        column: fact.column,
                        kind: "comparison",
                        text: &fact.text,
                    })
                }));
                selecting.extend(facts.modulo.iter().filter_map(|fact| {
                    mentions_ledger(&fact.text).then_some(SelectingExpression {
                        line: fact.line,
                        column: fact.column,
                        kind: "modulo",
                        text: &fact.text,
                    })
                }));
                selecting.extend(facts.arithmetic_ops().iter().filter_map(|fact| {
                    mentions_ledger(&fact.text).then_some(SelectingExpression {
                        line: fact.line,
                        column: fact.column,
                        kind: "arithmetic",
                        text: &fact.text,
                    })
                }));
                selecting.sort_by_key(|expression| (expression.line, expression.column));

                // A timestamp used only for an expiry check against a stored
                // deadline is not randomness.
                if !selecting.is_empty()
                    && selecting.iter().all(|expression| {
                        expression.kind == "comparison" && looks_like_deadline(expression.text)
                    })
                {
                    continue;
                }

                for access in accesses {
                    let Some(expression) = selecting
                        .iter()
                        .find(|expression| expression.text.contains(access.name.as_str()))
                    else {
                        continue;
                    };
                    let location = location_for(ctx, source, access.line, access.column);
                    let evidence = format!(
                        "ledger `{}` may be predictable and is used in an outcome-selecting {} in entry point `{}`: {}",
                        access.name, expression.kind, func.name, expression.text
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
    fn flags_timestamp_modulo() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Lottery {
                pub fn draw(env: Env) -> u32 {
                    (env.ledger().timestamp() % 100) as u32
                }
            }
            "#,
            Box::new(InsecureRandomness),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-009");
        assert!(findings[0].evidence.contains("timestamp"));
        assert!(findings[0].evidence.contains("modulo"));
    }

    #[test]
    fn flags_sequence_comparison() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Lottery {
                pub fn winner(env: Env, threshold: u32) -> bool {
                    env.ledger().sequence() > threshold
                }
            }
            "#,
            Box::new(InsecureRandomness),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("sequence"));
        assert!(findings[0].evidence.contains("comparison"));
    }

    #[test]
    fn does_not_flag_expiry_against_a_stored_deadline() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Auction {
                pub fn close(env: Env) {
                    let deadline: u64 = env
                        .storage()
                        .persistent()
                        .get(&DataKey::Deadline)
                        .unwrap();
                    if env.ledger().timestamp() > deadline {
                        env.storage().persistent().set(&DataKey::Closed, &true);
                    }
                }
            }
            "#,
            Box::new(InsecureRandomness),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_a_timestamp_read_without_an_operation() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Clock {
                pub fn now(env: Env) -> u64 {
                    env.ledger().timestamp()
                }
            }
            "#,
            Box::new(InsecureRandomness),
        );
        assert!(findings.is_empty());
    }
}
