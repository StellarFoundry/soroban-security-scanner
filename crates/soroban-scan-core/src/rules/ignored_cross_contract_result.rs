//! SS-019: ignored cross-contract call result.

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
    description: "A contract entry point invokes a cross-contract client method \
and explicitly discards its return value (`let _ = client.call(...)` or an \
unhandled `client.try_*(...);` statement). Ignoring a `try_*` result or \
discarding a cross-contract return value can allow execution to continue after \
the remote contract failed or returned a status that must be checked.",
    category: Category::CrossContract,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Handle the result of every cross-contract call explicitly. \
When using `try_*` client methods, propagate or match on the outer and inner \
`Result` values instead of discarding them with `let _ =` or a bare statement.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/contract-development/contract-interactions/cross-contract-calls"],
};

/// Detects cross-contract client calls whose return value is discarded.
pub struct IgnoredCrossContractResult;

struct IgnoredCallVisitor<'a> {
    imports: &'a ImportMap,
    client_vars: BTreeSet<String>,
    ignored: Vec<(usize, usize, String)>,
}

impl<'a> IgnoredCallVisitor<'a> {
    fn is_client_receiver(&self, expr: &syn::Expr) -> bool {
        match expr {
            syn::Expr::Path(path) if path.path.segments.len() == 1 => {
                let ident = path.path.segments[0].ident.to_string();
                self.client_vars.contains(&ident)
            }
            syn::Expr::Call(call) => {
                if let syn::Expr::Path(path) = &*call.func {
                    let name = path
                        .path
                        .segments
                        .last()
                        .map(|s| s.ident.to_string())
                        .unwrap_or_default();
                    let ctx = self
                        .imports
                        .canonicalize(&path.path.to_token_stream().to_string());
                    name == "new" && ctx.contains("Client")
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

impl<'ast, 'a> Visit<'ast> for IgnoredCallVisitor<'a> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
            if let syn::Expr::Call(call) = &*init.expr {
                if let syn::Expr::Path(path) = &*call.func {
                    let name = path
                        .path
                        .segments
                        .last()
                        .map(|s| s.ident.to_string())
                        .unwrap_or_default();
                    let context = self
                        .imports
                        .canonicalize(&path.path.to_token_stream().to_string());
                    if name == "new" && context.contains("Client") {
                        self.client_vars.insert(pattern.ident.to_string());
                    }
                }
            }
        }
        if let (syn::Pat::Wild(_), Some(init)) = (&node.pat, &node.init) {
            if let syn::Expr::MethodCall(call) = &*init.expr {
                if self.is_client_receiver(&call.receiver) {
                    let start = call.span().start();
                    self.ignored.push((
                        start.line,
                        start.column + 1,
                        node.to_token_stream().to_string(),
                    ));
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        if let syn::Stmt::Expr(syn::Expr::MethodCall(call), Some(_)) = node {
            let method = call.method.to_string();
            if self.is_client_receiver(&call.receiver) && method.starts_with("try_") {
                let start = call.span().start();
                self.ignored.push((
                    start.line,
                    start.column + 1,
                    call.to_token_stream().to_string(),
                ));
            }
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
                if !func.is_public {
                    continue;
                }
                let mut visitor = IgnoredCallVisitor {
                    imports: &source.imports,
                    client_vars: BTreeSet::new(),
                    ignored: Vec::new(),
                };
                visitor.visit_block(func.block);
                for (line, column, text) in visitor.ignored {
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!(
                        "ignored cross-contract call result in `{}`: {}",
                        func.name, text
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
    fn flags_wildcard_discarded_client_call() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn notify(env: Env, remote: Address, user: Address) {
                    user.require_auth();
                    let client = HookClient::new(&env, &remote);
                    let _ = client.try_on_deposit(&user);
                }
            }
            "#,
            Box::new(IgnoredCrossContractResult),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-019");
    }

    #[test]
    fn flags_bare_try_method_statement() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn notify(env: Env, remote: Address, user: Address) {
                    user.require_auth();
                    let client = HookClient::new(&env, &remote);
                    client.try_on_deposit(&user);
                }
            }
            "#,
            Box::new(IgnoredCrossContractResult),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-019");
    }

    #[test]
    fn does_not_flag_checked_or_direct_client_call() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn notify(env: Env, remote: Address, user: Address) -> bool {
                    user.require_auth();
                    let client = HookClient::new(&env, &remote);
                    client.try_on_deposit(&user).is_ok()
                }
            }
            "#,
            Box::new(IgnoredCrossContractResult),
        );
        assert!(findings.is_empty());
    }
}
