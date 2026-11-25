//! SS-019: the result of a cross-contract client call is ignored.

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
    id: "SS-019",
    title: "Ignored cross-contract call result",
    description: "A cross-contract client call is used as a bare statement, so \
its `Result` is discarded instead of being propagated with `?`, matched, or \
checked with `if let`. A failed call then looks successful to the caller, which \
can leave accounting, balances, or emitted state inconsistent. The detector only \
reports calls whose result is discarded; calls assigned, returned, or handled are \
ignored.",
    category: Category::CrossContract,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Handle the client call result: propagate it with `?`, match on \
`Ok`/`Err`, use `if let`, or explicitly document and log an intentional ignore. \
Never leave a fallible cross-contract call as a bare statement or in `let _ =`.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
        "https://developers.stellar.org/docs/build/guides/contract-interactions",
    ],
};

/// Detects cross-contract client calls whose result is discarded.
pub struct IgnoredCrossContractResult;

struct ClientCallVisitor<'a> {
    imports: &'a ImportMap,
    client_vars: BTreeSet<String>,
    ignored: Vec<(usize, usize, String)>,
}

impl ClientCallVisitor<'_> {
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
        let context = self
            .imports
            .canonicalize(&path.path.to_token_stream().to_string());
        context.contains("Client")
    }

    fn check_ignored(&mut self, expr: &syn::Expr) {
        let mut current = expr;
        loop {
            match current {
                syn::Expr::Paren(paren) => current = &paren.expr,
                syn::Expr::Group(group) => current = &group.expr,
                _ => break,
            }
        }
        let syn::Expr::MethodCall(call) = current else {
            return;
        };
        let syn::Expr::Path(path) = &*call.receiver else {
            return;
        };
        if path.path.segments.len() != 1 {
            return;
        }
        let receiver = path.path.segments[0].ident.to_string();
        if !self.client_vars.contains(&receiver) {
            return;
        }
        let start = call.span().start();
        self.ignored.push((
            start.line,
            start.column + 1,
            truncate(&call.to_token_stream().to_string(), 160),
        ));
    }
}

impl<'ast> Visit<'ast> for ClientCallVisitor<'_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
            if self.is_client_constructor(&init.expr) {
                self.client_vars.insert(pattern.ident.to_string());
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        match node {
            syn::Stmt::Expr(expr, Some(_)) => self.check_ignored(expr),
            syn::Stmt::Local(local) => {
                if matches!(local.pat, syn::Pat::Wild(_)) {
                    if let Some(init) = &local.init {
                        self.check_ignored(&init.expr);
                    }
                }
            }
            _ => {}
        }
        visit::visit_stmt(self, node);
    }
}

impl Rule for IgnoredCrossContractResult {
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
                let mut visitor = ClientCallVisitor {
                    imports: &source.imports,
                    client_vars: BTreeSet::new(),
                    ignored: Vec::new(),
                };
                visitor.visit_block(func.block);
                for (line, column, text) in visitor.ignored {
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!(
                        "cross-contract client call result is discarded in `{}`: {}",
                        func.name, text
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

    fn source(signature: &str, body: &str) -> String {
        format!(
            r#"
            #[contractimpl]
            impl Vault {{
                pub fn probe{signature} {{
                    let client = {CLIENT};
                    {body}
                }}
            }}
            "#
        )
    }

    #[test]
    fn flags_discarded_results() {
        let mut harness = RuleHarness::new(Box::new(IgnoredCrossContractResult));
        harness.positive(
            "bare client call statement",
            &source("(env: Env, who: Address)", "client.balance(&who);"),
            1,
        );
        harness.positive(
            "wildcard binding",
            &source("(env: Env, who: Address)", "let _ = client.balance(&who);"),
            1,
        );
        harness.run();
    }

    #[test]
    fn does_not_flag_assigned_or_returned_calls() {
        let mut harness = RuleHarness::new(Box::new(IgnoredCrossContractResult));
        harness.negative(
            "named binding",
            &source(
                "(env: Env, who: Address) -> i128",
                "let value = client.balance(&who); value",
            ),
        );
        harness.negative(
            "tail expression",
            &source("(env: Env, who: Address) -> i128", "client.balance(&who)"),
        );
        harness.run();
    }

    #[test]
    fn does_not_flag_handled_results() {
        let mut harness = RuleHarness::new(Box::new(IgnoredCrossContractResult));
        harness.negative(
            "propagated with ?",
            &source(
                "(env: Env, who: Address)",
                "let _ = client.try_balance(&who)?;",
            ),
        );
        harness.negative(
            "matched",
            &source(
                "(env: Env, who: Address)",
                "match client.try_balance(&who) { Ok(_) => {}, Err(_) => {} }",
            ),
        );
        harness.run();
    }

    #[test]
    fn does_not_guess_ambiguous_receivers() {
        let mut harness = RuleHarness::new(Box::new(IgnoredCrossContractResult));
        harness.ambiguous(
            "helper receiver",
            &source(
                "(env: Env, who: Address)",
                "let helper = client.balance(&who); helper.log(&who);",
            ),
            "the receiver is no longer a tracked client variable",
        );
        harness.run();
    }
}
