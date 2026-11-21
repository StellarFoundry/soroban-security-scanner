//! SS-032: redundant `require_auth` in a loop.

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
    id: "SS-032",
    title: "Redundant require_auth in loop",
    description: "A contract entry point calls `require_auth` (or \
`require_auth_for_args`) inside a loop body. Each iteration repeats an expensive \
authorization check for the same operation, and the repeated per-item check often \
means the authorization should be hoisted and bound to the operation's arguments \
once. This is a resource-efficiency heuristic, not a proof of a security bug.",
    category: Category::Authorization,
    default_severity: Severity::Low,
    default_confidence: Confidence::Medium,
    remediation: "Authorize once before the loop, for example \
`admin.require_auth();` followed by the loop, or use \
`require_auth_for_args` with the complete argument set the operation depends on. \
If every iteration genuinely authorizes a different actor, document why the \
per-iteration check is required.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects `require_auth` calls lexically inside loop bodies.
pub struct RedundantRequireAuthInLoop;

#[derive(Default)]
struct AuthInLoopVisitor {
    loop_depth: usize,
    calls: Vec<(usize, usize, String, String)>,
}

impl<'ast> Visit<'ast> for AuthInLoopVisitor {
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.loop_depth += 1;
        visit::visit_expr_for_loop(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.loop_depth += 1;
        visit::visit_expr_while(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.loop_depth += 1;
        visit::visit_expr_loop(self, node);
        self.loop_depth -= 1;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.loop_depth > 0 {
            let name = node.method.to_string();
            if name == "require_auth" || name == "require_auth_for_args" {
                let start = node.span().start();
                self.calls.push((
                    start.line,
                    start.column + 1,
                    name,
                    truncate(&node.to_token_stream().to_string(), 160),
                ));
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

impl Rule for RedundantRequireAuthInLoop {
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
                let mut visitor = AuthInLoopVisitor::default();
                visitor.visit_block(func.block);
                for (line, column, name, text) in visitor.calls {
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!(
                        "`{name}` called inside a loop in entry point `{}`: {text}",
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
    fn flags_require_auth_inside_for_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn pay(env: Env, admin: Address, recipients: Vec<Address>) {
                    for recipient in recipients {
                        admin.require_auth();
                        recipient.require_auth();
                    }
                }
            }
            "#,
            Box::new(RedundantRequireAuthInLoop),
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "SS-032");
        assert!(findings[0].evidence.contains("inside a loop"));
    }

    #[test]
    fn flags_require_auth_inside_while_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn drain(env: Env, admin: Address, mut remaining: u32) {
                    while remaining > 0 {
                        admin.require_auth();
                        remaining -= 1;
                    }
                }
            }
            "#,
            Box::new(RedundantRequireAuthInLoop),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_hoisted_authorization() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn pay(env: Env, admin: Address, recipients: Vec<Address>) {
                    admin.require_auth();
                    for recipient in recipients {
                        transfer(&env, &recipient);
                    }
                }
            }
            "#,
            Box::new(RedundantRequireAuthInLoop),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_authorization_outside_a_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address) {
                    admin.require_auth();
                }
            }
            "#,
            Box::new(RedundantRequireAuthInLoop),
        );
        assert!(findings.is_empty());
    }
}
