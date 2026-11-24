//! SS-045: a cross-contract call result is neither propagated nor handled.

use std::collections::BTreeSet;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::imports::ImportMap;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-045",
    title: "Cross-contract call without error handling",
    description: "A cross-contract client call result inside an entry point is \
neither propagated with `?` nor explicitly handled with `match`, `if let`, or a \
documented `unwrap`/`unwrap_or*`/`expect`/`map_err` combination. A failed call \
then looks successful, which can leave accounting or balances inconsistent. \
Ambiguous uses are not reported.",
    category: Category::CrossContract,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Propagate the result with `?`, match on the error, use `if \
let`, or explicitly map the failure to a contract error. If a result is \
intentionally ignored, bind it to a name starting with `_` and document why.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
        "https://developers.stellar.org/docs/build/guides/contract-errors",
    ],
};

/// Detects cross-contract client calls whose result is not handled.
pub struct CrossContractErrorHandling;

struct ClientVarVisitor<'a> {
    imports: &'a ImportMap,
    client_vars: BTreeSet<String>,
}

impl ClientVarVisitor<'_> {
    fn is_client_constructor(&self, expr: &syn::Expr) -> bool {
        let syn::Expr::Call(call) = expr else {
            return false;
        };
        let syn::Expr::Path(path) = &*call.func else {
            return false;
        };
        let Some(segment) = path.path.segments.last() else {
            return false;
        };
        if segment.ident != "new" {
            return false;
        }
        self.imports
            .canonicalize(&path.path.to_token_stream().to_string())
            .contains("Client")
    }
}

impl<'ast> Visit<'ast> for ClientVarVisitor<'_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
            if self.is_client_constructor(&init.expr) {
                self.client_vars.insert(pattern.ident.to_string());
            }
        }
        visit::visit_local(self, node);
    }
}

struct ResultUseVisitor<'a> {
    client_vars: &'a BTreeSet<String>,
    ignored: Vec<(usize, usize, String)>,
    /// Direct client-call bindings, checked for later use.
    bindings: Vec<(String, usize, usize, String)>,
    used: BTreeSet<String>,
}

impl ResultUseVisitor<'_> {
    fn is_client_call(&self, call: &syn::ExprMethodCall) -> bool {
        let syn::Expr::Path(path) = &*call.receiver else {
            return false;
        };
        let Some(ident) = path.path.get_ident() else {
            return false;
        };
        self.client_vars.contains(&ident.to_string())
    }

    fn push_ignored(&mut self, call: &syn::ExprMethodCall) {
        let start = call.span().start();
        self.ignored.push((
            start.line,
            start.column + 1,
            truncate(&call.to_token_stream().to_string(), 160),
        ));
    }
}

/// Strips parentheses and groups that do not change value semantics.
fn strip(expr: &syn::Expr) -> &syn::Expr {
    let mut current = expr;
    loop {
        match current {
            syn::Expr::Paren(paren) => current = &paren.expr,
            syn::Expr::Group(group) => current = &group.expr,
            _ => return current,
        }
    }
}

impl<'ast> Visit<'ast> for ResultUseVisitor<'_> {
    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if let Some(ident) = node.path.get_ident() {
            self.used.insert(ident.to_string());
        }
        visit::visit_expr_path(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init {
            if let syn::Expr::MethodCall(call) = strip(&init.expr) {
                if self.is_client_call(call) {
                    match &node.pat {
                        syn::Pat::Wild(_) => self.push_ignored(call),
                        syn::Pat::Ident(pattern) => {
                            let name = pattern.ident.to_string();
                            // An underscore prefix is the documented way to
                            // ignore a value intentionally.
                            if !name.starts_with('_') {
                                let start = call.span().start();
                                self.bindings.push((
                                    name,
                                    start.line,
                                    start.column + 1,
                                    truncate(&call.to_token_stream().to_string(), 160),
                                ));
                            }
                        }
                        // Destructuring is ambiguous: the parts may be handled.
                        _ => {}
                    }
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Expr(expr, Some(_)) = node {
            if let syn::Expr::MethodCall(call) = strip(expr) {
                if self.is_client_call(call) {
                    self.push_ignored(call);
                }
            }
        }
        visit::visit_stmt(self, node);
    }
}

impl Rule for CrossContractErrorHandling {
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
                let mut var_visitor = ClientVarVisitor {
                    imports: &source.imports,
                    client_vars: BTreeSet::new(),
                };
                var_visitor.visit_block(func.block);
                let client_vars = var_visitor.client_vars;
                if client_vars.is_empty() {
                    continue;
                }

                let mut visitor = ResultUseVisitor {
                    client_vars: &client_vars,
                    ignored: Vec::new(),
                    bindings: Vec::new(),
                    used: BTreeSet::new(),
                };
                visitor.visit_block(func.block);

                for (name, line, column, text) in visitor.bindings {
                    if visitor.used.contains(&name) {
                        continue;
                    }
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!(
                        "cross-contract call result bound to `{name}` is neither \
propagated nor handled in `{}`: {text}",
                        func.name
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
                for (line, column, text) in visitor.ignored {
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!(
                        "cross-contract call result is discarded in `{}`: {text}",
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
    use crate::rules::test_support::RuleHarness;

    const CLIENT: &str = "token::Client::new(&env, TOKEN)";

    fn source(body: &str) -> String {
        format!(
            r#"
            #[contractimpl]
            impl Vault {{
                pub fn probe(env: Env, who: Address) {{
                    let client = {CLIENT};
                    {body}
                }}
            }}
            "#
        )
    }

    #[test]
    fn flags_discarded_and_unused_results() {
        let mut harness = RuleHarness::new(Box::new(CrossContractErrorHandling));
        harness.positive(
            "discarded into let _",
            &source("let _ = client.balance(&who);"),
            1,
        );
        harness.positive(
            "unused named binding",
            &source("let value = client.balance(&who);"),
            1,
        );
        harness.run();
    }

    #[test]
    fn does_not_flag_handled_results() {
        let mut harness = RuleHarness::new(Box::new(CrossContractErrorHandling));
        harness.negative(
            "propagated with ?",
            &source("let value = client.balance(&who)?; let _ = value;"),
        );
        harness.negative(
            "matched and inspected",
            &source("match client.try_balance(&who) { Ok(_) => {}, Err(_) => {} }"),
        );
        harness.negative(
            "mapped with unwrap_or",
            &source("let value = client.balance(&who).unwrap_or(0); let _ = value;"),
        );
        harness.run();
    }

    #[test]
    fn does_not_guess_ambiguous_uses() {
        let mut harness = RuleHarness::new(Box::new(CrossContractErrorHandling));
        harness.ambiguous(
            "passed to a free function",
            &source("consume(client.balance(&who));"),
            "the callee may handle the result",
        );
        harness.ambiguous(
            "underscore-prefixed binding",
            &source("let _ignored = client.balance(&who);"),
            "an underscore name is the documented intentional ignore",
        );
        harness.run();
    }
}
