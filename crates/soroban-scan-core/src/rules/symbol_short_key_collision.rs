//! SS-022: `symbol_short!` key longer than the limit or built from user input.

use std::collections::BTreeSet;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, ContractFn};

/// Maximum number of characters accepted by `symbol_short!` in supported SDKs.
///
/// Soroban's short-symbol encoding stores at most nine ASCII characters
/// (soroban-sdk 20.x through 23.x). `symbol_short!` panics at compile time for a
/// longer literal, so any accepted short symbol has at most nine characters.
pub const SYMBOL_SHORT_MAX_CHARS: usize = 9;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-022",
    title: "Unsafe symbol_short key",
    description: "A contract uses `symbol_short!` with a literal longer than the \
nine-character short-symbol limit, or builds the symbol from caller-controlled \
input. Overlong literals do not describe the symbol the author expects once \
truncated or fail to compile, while caller-built short symbols can deliberately \
collide with another key and overwrite or misread storage. This is a syntactic \
heuristic and reports medium confidence.",
    category: Category::Storage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Use a constant literal of at most nine characters such as \
`symbol_short!(\"transfer\")`, or use `Symbol::new(&env, value)` for longer or \
dynamic values. Never derive a storage key directly from caller input; map it \
through an allowlist of known keys.",
    references: &[
        "https://docs.rs/soroban-sdk/latest/soroban_sdk/macro.symbol_short.html",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects overlong and caller-controlled `symbol_short!` keys.
pub struct SymbolShortKeyCollision;

fn caller_params(func: &ContractFn<'_>) -> BTreeSet<String> {
    func.param_types
        .iter()
        .filter(|(_, ty)| !ty.trim().trim_start_matches('&').trim().starts_with("Env"))
        .map(|(name, _)| name.clone())
        .collect()
}

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

/// Parameters plus simple local aliases derived from caller input.
fn caller_derived_names(func: &ContractFn<'_>) -> BTreeSet<String> {
    let mut derived = caller_params(func);

    struct AliasVisitor<'a> {
        derived: &'a BTreeSet<String>,
        discovered: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for AliasVisitor<'_> {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
                let text = init.expr.to_token_stream().to_string();
                if self.derived.iter().any(|name| mentions_ident(&text, name)) {
                    self.discovered.insert(pattern.ident.to_string());
                }
            }
            visit::visit_local(self, node);
        }
    }

    loop {
        let mut visitor = AliasVisitor {
            derived: &derived,
            discovered: BTreeSet::new(),
        };
        visitor.visit_block(func.block);
        let before = derived.len();
        derived.extend(visitor.discovered);
        if derived.len() == before {
            break;
        }
    }
    derived
}

struct SymbolVisitor<'a> {
    derived: &'a BTreeSet<String>,
    findings: Vec<(usize, usize, String)>,
}

impl<'ast, 'a> Visit<'ast> for SymbolVisitor<'a> {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let is_symbol_short = node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "symbol_short");
        if !is_symbol_short {
            visit::visit_macro(self, node);
            return;
        }

        let start = node.span().start();
        let line = start.line;
        let column = start.column + 1;

        match syn::parse2::<syn::LitStr>(node.tokens.clone()) {
            Ok(literal) => {
                let value = literal.value();
                let length = value.chars().count();
                if length > SYMBOL_SHORT_MAX_CHARS {
                    self.findings.push((
                        line,
                        column,
                        format!(
                            "`symbol_short!(\"{value}\")` is {length} characters, longer than \
                             the {SYMBOL_SHORT_MAX_CHARS}-character short-symbol limit"
                        ),
                    ));
                }
            }
            Err(_) => {
                let rendered = node.tokens.to_string();
                if let Some(name) = self
                    .derived
                    .iter()
                    .find(|name| mentions_ident(&rendered, name))
                {
                    self.findings.push((
                        line,
                        column,
                        format!(
                            "`symbol_short!` key is built from caller-controlled `{name}`: {}",
                            truncate(&rendered, 120)
                        ),
                    ));
                }
            }
        }

        visit::visit_macro(self, node);
    }
}

impl Rule for SymbolShortKeyCollision {
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
                let derived = caller_derived_names(&func);
                let mut visitor = SymbolVisitor {
                    derived: &derived,
                    findings: Vec::new(),
                };
                visitor.visit_block(func.block);
                for (line, column, detail) in visitor.findings {
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!(
                        "unsafe short symbol in entry point `{}`: {detail}",
                        func.name
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_overlong_literal() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Env};

            #[contractimpl]
            impl C {
                pub fn store(env: Env) {
                    let key = symbol_short!("this_is_too_long");
                    env.storage().persistent().set(&key, &1);
                }
            }
            "#,
            Box::new(SymbolShortKeyCollision),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-022");
        assert!(findings[0].evidence.contains("longer than"));
    }

    #[test]
    fn flags_symbol_built_from_parameter() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Env, String};

            #[contractimpl]
            impl C {
                pub fn store(env: Env, key: String) {
                    let symbol = symbol_short!(key);
                    env.storage().persistent().set(&symbol, &1);
                }
            }
            "#,
            Box::new(SymbolShortKeyCollision),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("caller-controlled `key`"));
    }

    #[test]
    fn flags_symbol_built_from_local_alias() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Env, String};

            #[contractimpl]
            impl C {
                pub fn store(env: Env, key: String) {
                    let raw = key;
                    let _ = symbol_short!(raw);
                }
            }
            "#,
            Box::new(SymbolShortKeyCollision),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("caller-controlled `raw`"));
    }

    #[test]
    fn does_not_flag_nine_character_literal() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Env};

            #[contractimpl]
            impl C {
                pub fn store(env: Env) {
                    let key = symbol_short!("123456789");
                    env.storage().persistent().set(&key, &1);
                }
            }
            "#,
            Box::new(SymbolShortKeyCollision),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_constant_identifier() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Env};

            const KEY: &str = "balance";

            #[contractimpl]
            impl C {
                pub fn store(env: Env) {
                    let key = symbol_short!(KEY);
                    env.storage().persistent().set(&key, &1);
                }
            }
            "#,
            Box::new(SymbolShortKeyCollision),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Env, String};

            #[contractimpl]
            impl C {
                fn store(env: Env, key: String) {
                    let _ = symbol_short!(key);
                }
            }
            "#,
            Box::new(SymbolShortKeyCollision),
        );
        assert!(findings.is_empty());
    }
}
