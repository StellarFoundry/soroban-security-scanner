//! SS-035: the result of a checked arithmetic operation is ignored.

use std::collections::BTreeSet;

use proc_macro2::Span;
use quote::ToTokens;
use syn::spanned::Spanned;
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
    id: "SS-035",
    title: "Ignored checked-arithmetic result",
    description: "A `checked_add`/`checked_sub`/`checked_mul` (or similar) \
result is discarded or bound without being inspected. Overflow then silently \
produces `None`, reintroducing the bug the checked API exists to prevent. The \
detector reports calls whose result is not directly consumed by `?`, `match`, or \
an `unwrap`/`unwrap_or`-style handler.",
    category: Category::Arithmetic,
    default_severity: Severity::High,
    default_confidence: Confidence::Medium,
    remediation: "Handle the checked result: use `?` to propagate it, match on \
`Some`/`None`, or supply a fallback with `unwrap_or`/`unwrap_or_else`. Never use \
`checked_*` as a bare statement or discard it into `_`.",
    references: &[
        "https://doc.rust-lang.org/std/primitive.i128.html#method.checked_add",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects checked arithmetic whose result is not consumed.
pub struct IgnoredCheckedResult;

const CHECKED_METHODS: &[&str] = &[
    "checked_add",
    "checked_sub",
    "checked_mul",
    "checked_div",
    "checked_rem",
    "checked_neg",
    "checked_abs",
    "checked_pow",
    "checked_shl",
    "checked_shr",
];

const HANDLERS: &[&str] = &[
    "unwrap",
    "expect",
    "unwrap_or",
    "unwrap_or_else",
    "unwrap_or_default",
    "is_some",
    "is_none",
    "is_ok",
    "is_err",
    "ok_or",
    "ok_or_else",
    "map",
    "map_or",
    "map_or_else",
    "and_then",
    "or_else",
    "filter",
];

struct CheckedCall {
    range: (usize, usize),
    line: usize,
    column: usize,
    text: String,
}

#[derive(Default)]
struct CheckedVisitor {
    calls: Vec<CheckedCall>,
    handled: BTreeSet<(usize, usize)>,
}

fn is_checked(name: &str) -> bool {
    CHECKED_METHODS.contains(&name)
}

fn is_handler(name: &str) -> bool {
    HANDLERS.contains(&name)
}

fn range_of(span: Span) -> (usize, usize) {
    let range = span.byte_range();
    (range.start, range.end)
}

fn checked_name_of_call(call: &syn::ExprCall) -> Option<String> {
    if let syn::Expr::Path(path) = &*call.func {
        return path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
    }
    None
}

impl CheckedVisitor {
    fn mark_if_checked(&mut self, expr: &syn::Expr) {
        match expr {
            syn::Expr::MethodCall(call) if is_checked(&call.method.to_string()) => {
                self.handled.insert(range_of(call.span()));
            }
            syn::Expr::Call(call)
                if checked_name_of_call(call).is_some_and(|name| is_checked(&name)) =>
            {
                self.handled.insert(range_of(call.span()));
            }
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for CheckedVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if is_checked(&name) {
            let start = node.span().start();
            self.calls.push(CheckedCall {
                range: range_of(node.span()),
                line: start.line,
                column: start.column + 1,
                text: node.to_token_stream().to_string(),
            });
        }
        if is_handler(&name) {
            self.mark_if_checked(&node.receiver);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if checked_name_of_call(node).is_some_and(|name| is_checked(&name)) {
            let start = node.span().start();
            self.calls.push(CheckedCall {
                range: range_of(node.span()),
                line: start.line,
                column: start.column + 1,
                text: node.to_token_stream().to_string(),
            });
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        self.mark_if_checked(&node.expr);
        visit::visit_expr_try(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.mark_if_checked(&node.expr);
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
        if let Some(expr) = &node.expr {
            self.mark_if_checked(expr);
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if let syn::Expr::Let(binding) = &*node.cond {
            self.mark_if_checked(&binding.expr);
        }
        visit::visit_expr_if(self, node);
    }
}

impl Rule for IgnoredCheckedResult {
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
                let mut visitor = CheckedVisitor::default();
                visitor.visit_block(func.block);
                for call in visitor.calls {
                    if visitor.handled.contains(&call.range) {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "checked-arithmetic result is not handled in entry point `{}`: {}",
                        func.name,
                        truncate(&call.text, 160)
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
    fn flags_discarded_checked_result_statement() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn add(env: Env, amount: i128) {
                    amount.checked_add(1);
                }
            }
            "#,
            Box::new(IgnoredCheckedResult),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-035");
    }

    #[test]
    fn flags_discarded_into_underscore() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn add(env: Env, amount: i128) {
                    let _ = amount.checked_mul(2);
                }
            }
            "#,
            Box::new(IgnoredCheckedResult),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_unwrap_or_fallback() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn add(env: Env, amount: i128) -> i128 {
                    amount.checked_add(1).unwrap_or(0)
                }
            }
            "#,
            Box::new(IgnoredCheckedResult),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_try_or_match_handling() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn add(env: Env, amount: i128) -> Option<i128> {
                    let value = amount.checked_add(1)?;
                    let other = match amount.checked_sub(1) {
                        Some(v) => v,
                        None => 0,
                    };
                    Some(value + other)
                }
            }
            "#,
            Box::new(IgnoredCheckedResult),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn add(env: Env, amount: i128) {
                    amount.checked_add(1);
                }
            }
            "#,
            Box::new(IgnoredCheckedResult),
        );
        assert!(findings.is_empty());
    }
}
