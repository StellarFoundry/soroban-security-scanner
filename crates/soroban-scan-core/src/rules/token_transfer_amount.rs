//! SS-014: token transfer amount without validation.

use std::collections::BTreeSet;

use syn::parse::Parser;
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
    id: "SS-014",
    title: "Token transfer amount without validation",
    description: "A public contract entry point passes a caller-supplied amount \
to `transfer` or `transfer_from` without comparing it against zero. Token \
implementations differ in how they treat negative or out-of-range amounts; a \
missing guard can therefore move an unintended value, corrupt accounting, or \
revert in surprising ways. This is a heuristic: it cannot prove that the token \
rejects the value or that another layer validates it, so it reports low \
confidence.",
    category: Category::Token,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Validate the amount before transferring, for example reject \
`amount <= 0` with a typed contract error (or check both bounds when the token \
has a maximum). Validate once at the entry point and pass the checked value to \
`transfer`/`transfer_from`.",
    references: &[
        "https://developers.stellar.org/docs/tokens/token-interface",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects token transfers whose amount parameter is not validated.
pub struct TokenTransferAmount;

/// Method names that move tokens and take the amount as their last argument.
const TRANSFER_METHODS: &[&str] = &["transfer", "transfer_from"];

/// A transfer call whose amount argument is a simple identifier.
struct TransferCall {
    method: String,
    amount: String,
    line: usize,
    column: usize,
}

#[derive(Default)]
struct TransferCallVisitor {
    calls: Vec<TransferCall>,
}

impl<'ast> Visit<'ast> for TransferCallVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if TRANSFER_METHODS.contains(&method.as_str()) {
            if let Some(amount) = node.args.last().and_then(identifier_of) {
                let start = node.span().start();
                self.calls.push(TransferCall {
                    method,
                    amount: amount.to_string(),
                    line: start.line,
                    column: start.column + 1,
                });
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

/// Returns the single identifier inside an expression, following references,
/// parentheses, and groups (`amount`, `&amount`, `(&amount)`).
fn identifier_of(expr: &syn::Expr) -> Option<&syn::Ident> {
    match expr {
        syn::Expr::Path(path) if path.qself.is_none() => path.path.get_ident(),
        syn::Expr::Reference(reference) => identifier_of(&reference.expr),
        syn::Expr::Paren(paren) => identifier_of(&paren.expr),
        syn::Expr::Group(group) => identifier_of(&group.expr),
        _ => None,
    }
}

/// Whether an expression mentions `name` as a path segment.
fn mentions_ident(expr: &syn::Expr, name: &str) -> bool {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .iter()
            .any(|segment| segment.ident == name),
        syn::Expr::Reference(reference) => mentions_ident(&reference.expr, name),
        syn::Expr::Paren(paren) => mentions_ident(&paren.expr, name),
        syn::Expr::Group(group) => mentions_ident(&group.expr, name),
        syn::Expr::Unary(unary) => mentions_ident(&unary.expr, name),
        syn::Expr::Cast(cast) => mentions_ident(&cast.expr, name),
        _ => false,
    }
}

/// Whether an expression is the integer literal zero.
fn is_zero_literal(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(int) => int.base10_digits() == "0",
            _ => false,
        },
        syn::Expr::Paren(paren) => is_zero_literal(&paren.expr),
        syn::Expr::Group(group) => is_zero_literal(&group.expr),
        _ => false,
    }
}

/// Finds an inequality comparison between `name` and zero (`amount <= 0`,
/// `0 < amount`, ...), which is treated as a validation guard.
struct ZeroGuardVisitor<'a> {
    name: &'a str,
    found: bool,
}

impl<'ast, 'a> Visit<'ast> for ZeroGuardVisitor<'a> {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if !self.found {
            let inequality = matches!(
                node.op,
                syn::BinOp::Lt(_) | syn::BinOp::Le(_) | syn::BinOp::Gt(_) | syn::BinOp::Ge(_)
            );
            if inequality
                && ((mentions_ident(&node.left, self.name) && is_zero_literal(&node.right))
                    || (mentions_ident(&node.right, self.name) && is_zero_literal(&node.left)))
            {
                self.found = true;
            }
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if !self.found {
            // Guards are frequently written as `assert!(amount > 0, "...")`.
            // Macro arguments are tokens rather than `syn::Expr` nodes, so
            // parse the comma-separated expressions and visit them explicitly.
            let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
            if let Ok(expressions) = parser.parse2(node.tokens.clone()) {
                for expression in &expressions {
                    self.visit_expr(expression);
                }
            }
        }
        visit::visit_macro(self, node);
    }
}

/// Returns true when the block compares `name` against zero.
fn has_zero_guard(block: &syn::Block, name: &str) -> bool {
    let mut visitor = ZeroGuardVisitor { name, found: false };
    visitor.visit_block(block);
    visitor.found
}

impl Rule for TokenTransferAmount {
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
                let params: BTreeSet<&str> = func.params.iter().map(String::as_str).collect();
                let mut visitor = TransferCallVisitor::default();
                visitor.visit_block(func.block);

                for call in visitor.calls {
                    // Only an unchecked parameter is in scope. Values read from
                    // storage, literals, and computed expressions are ignored.
                    if !params.contains(call.amount.as_str()) {
                        continue;
                    }
                    if has_zero_guard(func.block, &call.amount) {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "`{}` transfers unchecked amount `{}` in entry point `{}`",
                        call.method, call.amount, func.name
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

    const TRANSFER: &str = r#"
        use soroban_sdk::{contractimpl, token, Address, Env};

        #[contractimpl]
        impl Vault {
            pub fn payout(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
                from.require_auth();
                let client = token::Client::new(&env, &token_id);
                client.transfer(&from, &to, &amount);
            }
        }
    "#;

    #[test]
    fn flags_unchecked_transfer_amount() {
        let findings = scan_rule(TRANSFER, Box::new(TokenTransferAmount));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-014");
        assert!(findings[0].evidence.contains("unchecked amount `amount`"));
    }

    #[test]
    fn flags_unchecked_transfer_from_amount() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl Vault {
                pub fn pull(env: Env, token_id: Address, spender: Address, from: Address, to: Address, amount: i128) {
                    spender.require_auth();
                    let client = token::Client::new(&env, &token_id);
                    client.transfer_from(&spender, &from, &to, &amount);
                }
            }
            "#,
            Box::new(TokenTransferAmount),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("transfer_from"));
    }

    #[test]
    fn does_not_flag_amount_guarded_against_zero() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
                    from.require_auth();
                    if amount <= 0 {
                        panic!("amount must be positive");
                    }
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&from, &to, &amount);
                }
            }
            "#,
            Box::new(TokenTransferAmount),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_mirrored_zero_comparison() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
                    from.require_auth();
                    assert!(0 < amount, "amount must be positive");
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&from, &to, &amount);
                }
            }
            "#,
            Box::new(TokenTransferAmount),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_literal_or_computed_amounts() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, from: Address, to: Address, amount: i128) {
                    from.require_auth();
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&from, &to, &1i128);
                    client.transfer(&from, &to, &(amount - 1));
                }
            }
            "#,
            Box::new(TokenTransferAmount),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_non_parameter_amounts() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl Vault {
                pub fn payout(env: Env, token_id: Address, from: Address, to: Address) {
                    from.require_auth();
                    let amount: i128 = env.storage().instance().get(&0).unwrap_or(0);
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&from, &to, &amount);
                }
            }
            "#,
            Box::new(TokenTransferAmount),
        );
        assert!(findings.is_empty());
    }
}
