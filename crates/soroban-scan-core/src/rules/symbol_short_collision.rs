//! SS-022: `symbol_short!` key collision or invalid literal.

use std::collections::BTreeMap;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{facts_from_file_with_imports, location_for};

/// Maximum length of a `symbol_short!` literal in `soroban-sdk`.
pub const MAX_SYMBOL_SHORT_LEN: usize = 9;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-022",
    title: "Duplicate or invalid symbol_short! storage key",
    description: "Two distinct `Symbol` constants in the same contract file \
resolve to the same `symbol_short!` literal, or a `symbol_short!` invocation \
uses a literal longer than 9 characters or outside `[a-zA-Z0-9_]`. Duplicate \
key constants cause unrelated contract state to overwrite the same storage \
slot.",
    category: Category::Storage,
    default_severity: Severity::High,
    default_confidence: Confidence::High,
    remediation: "Assign a unique `symbol_short!` literal (at most 9 ASCII \
alphanumeric/underscore characters) to each storage key constant, or use a \
typed `#[contracttype] enum DataKey` so the compiler enforces distinct keys.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data"],
};

/// Detects colliding `symbol_short!` key constants and overlong/invalid literals.
pub struct SymbolShortCollision;

fn extract_symbol_short_literal(expr_text: &str) -> Option<String> {
    if !expr_text.contains("symbol_short") {
        return None;
    }
    let start = expr_text.find('"')? + 1;
    let end = expr_text[start..].find('"')? + start;
    Some(expr_text[start..end].to_string())
}

fn is_valid_symbol_short(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SYMBOL_SHORT_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

impl Rule for SymbolShortCollision {
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
            let mut seen_consts: BTreeMap<String, String> = BTreeMap::new();
            for c in &source.constants {
                let Some(lit) = extract_symbol_short_literal(&c.value) else {
                    continue;
                };
                if let Some(prev_name) = seen_consts.get(&lit) {
                    if prev_name != &c.qualified_name {
                        let location = location_for(ctx, source, c.line, c.column);
                        let evidence = format!(
                            "constant `{}` reuses `symbol_short!(\"{}\")` already assigned to `{}`",
                            c.qualified_name, lit, prev_name
                        );
                        out.push(Finding::new(&METADATA, location, evidence));
                    }
                } else {
                    seen_consts.insert(lit, c.qualified_name.clone());
                }
            }

            let facts = facts_from_file_with_imports(file, &source.imports);
            for s in &facts.strings {
                if s.origin == "symbol_short" && !is_valid_symbol_short(&s.value) {
                    let location = location_for(ctx, source, s.line, s.column);
                    let evidence = format!(
                        "invalid `symbol_short!(\"{}\")` literal (len {}, max {})",
                        s.value,
                        s.value.len(),
                        MAX_SYMBOL_SHORT_LEN
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
    fn flags_duplicate_symbol_short_constants() {
        let findings = scan_rule(
            r#"
            const ADMIN_KEY: Symbol = symbol_short!("ADMIN");
            const OWNER_KEY: Symbol = symbol_short!("ADMIN");

            #[contractimpl]
            impl C {
                pub fn init(env: Env) {}
            }
            "#,
            Box::new(SymbolShortCollision),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-022");
    }

    #[test]
    fn flags_overlong_symbol_short_literal() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn init(env: Env) {
                    let _k = symbol_short!("TOO_LONG_KEY");
                }
            }
            "#,
            Box::new(SymbolShortCollision),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-022");
    }

    #[test]
    fn does_not_flag_distinct_valid_keys() {
        let findings = scan_rule(
            r#"
            const ADMIN_KEY: Symbol = symbol_short!("ADMIN");
            const PAUSE_KEY: Symbol = symbol_short!("PAUSE");

            #[contractimpl]
            impl C {
                pub fn init(env: Env) {}
            }
            "#,
            Box::new(SymbolShortCollision),
        );
        assert!(findings.is_empty());
    }
}
