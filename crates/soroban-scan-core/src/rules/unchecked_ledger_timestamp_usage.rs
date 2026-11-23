//! SS-047: ledger timestamp comparisons without a bounded tolerance window.

use quote::ToTokens;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-047",
    title: "Unchecked ledger timestamp usage",
    description: "A contract entry point compares the ledger timestamp with a \
deadline or another timestamp without a visible tolerance or bounded window. \
Ledger time is chosen within protocol bounds and can move slightly between \
submission and execution, so an exact or zero-slack comparison can flip for \
transactions near the boundary. The detector reports ordered comparisons of a \
timestamp or a local timestamp alias when no tolerance arithmetic is visible, \
with low confidence.",
    category: Category::Arithmetic,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Compare against a bounded window instead of an exact boundary, \
for example `now + TOLERANCE >= deadline` or \
`now.saturating_sub(deadline) <= WINDOW`, with a named tolerance constant \
justified by the contract's timing model. Keep the window small and documented.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
        "https://developers.stellar.org/docs/learn/encyclopedia/contract-development",
    ],
};

/// Detects timestamp comparisons with no visible tolerance.
pub struct UncheckedLedgerTimestampUsage;

/// Substrings that indicate an intentional tolerance or bounded window.
const TOLERANCE_HINTS: &[&str] = &[
    "tolerance",
    "window",
    "slack",
    "grace",
    "skew",
    "margin",
    "buffer",
];

/// Checked or saturating arithmetic makes the comparison bounded by construction.
const BOUNDED_HINTS: &[&str] = &[
    "checked_add",
    "checked_sub",
    "saturating_add",
    "saturating_sub",
];

fn mentions_ident(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(needle) {
        let index = start + offset;
        let end = index + needle.len();
        let before = index == 0 || !is_ident_byte(bytes[index - 1]);
        let after = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before && after {
            return true;
        }
        start = end;
    }
    false
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_timestamp_expression(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("timestamp") && lower.contains("ledger")
}

/// Locals initialized from the ledger timestamp, including simple aliases.
fn timestamp_aliases(block: &syn::Block) -> Vec<String> {
    let mut aliases: Vec<String> = Vec::new();

    struct AliasVisitor<'a> {
        seeds: &'a [String],
        discovered: Vec<String>,
    }

    impl<'ast> Visit<'ast> for AliasVisitor<'_> {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
                let text = init.expr.to_token_stream().to_string();
                if is_timestamp_expression(&text)
                    || self.seeds.iter().any(|seed| mentions_ident(&text, seed))
                {
                    self.discovered.push(pattern.ident.to_string());
                }
            }
            visit::visit_local(self, node);
        }
    }

    loop {
        let visitor_aliases = aliases.clone();
        let mut visitor = AliasVisitor {
            seeds: &visitor_aliases,
            discovered: Vec::new(),
        };
        visitor.visit_block(block);
        let before = aliases.len();
        for alias in visitor.discovered {
            if !aliases.contains(&alias) {
                aliases.push(alias);
            }
        }
        if aliases.len() == before {
            return aliases;
        }
    }
}

impl Rule for UncheckedLedgerTimestampUsage {
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
                let function_text = func.block.to_token_stream().to_string();
                if BOUNDED_HINTS
                    .iter()
                    .any(|hint| function_text.contains(hint))
                {
                    continue;
                }

                let aliases = timestamp_aliases(func.block);
                let facts = ctx.facts_for_function(source, &func);
                for comparison in &facts.comparisons {
                    if !matches!(comparison.op.as_str(), "<" | "<=" | ">" | ">=") {
                        continue;
                    }
                    let uses_timestamp = is_timestamp_expression(&comparison.text)
                        || aliases
                            .iter()
                            .any(|alias| mentions_ident(&comparison.text, alias));
                    if !uses_timestamp || has_tolerance(&comparison.text) {
                        continue;
                    }
                    let location = location_for(ctx, source, comparison.line, comparison.column);
                    let evidence = format!(
                        "ledger timestamp comparison without a bounded tolerance window in \
                         entry point `{}`: {}",
                        func.name, comparison.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn has_tolerance(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    TOLERANCE_HINTS.iter().any(|hint| lower.contains(hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_timestamp_alias_compared_without_slack() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Auction {
                pub fn close(env: Env, deadline: u64) {
                    let now = env.ledger().timestamp();
                    if now >= deadline {
                        env.storage().persistent().set(&DataKey::Closed, &true);
                    }
                }
            }
            "#,
            Box::new(UncheckedLedgerTimestampUsage),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-047");
        assert!(findings[0].evidence.contains("now >= deadline"));
    }

    #[test]
    fn flags_direct_timestamp_comparison() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Auction {
                pub fn close(env: Env, deadline: u64) -> bool {
                    env.ledger().timestamp() > deadline
                }
            }
            "#,
            Box::new(UncheckedLedgerTimestampUsage),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_explicit_tolerance() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Auction {
                pub fn close(env: Env, deadline: u64, tolerance: u64) {
                    let now = env.ledger().timestamp();
                    if now + tolerance >= deadline {
                        env.storage().persistent().set(&DataKey::Closed, &true);
                    }
                }
            }
            "#,
            Box::new(UncheckedLedgerTimestampUsage),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_bounded_window_arithmetic() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Auction {
                pub fn close(env: Env, deadline: u64) {
                    let now = env.ledger().timestamp();
                    if now.checked_add(5).unwrap() >= deadline {
                        env.storage().persistent().set(&DataKey::Closed, &true);
                    }
                }
            }
            "#,
            Box::new(UncheckedLedgerTimestampUsage),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_non_timestamp_comparison() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Auction {
                pub fn open(env: Env, amount: u64, minimum: u64) -> bool {
                    env.ledger().timestamp();
                    amount >= minimum
                }
            }
            "#,
            Box::new(UncheckedLedgerTimestampUsage),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn only_ordered_comparisons_are_reported() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Auction {
                pub fn equal(env: Env, deadline: u64) -> bool {
                    env.ledger().timestamp() == deadline
                }
            }
            "#,
            Box::new(UncheckedLedgerTimestampUsage),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }
}
