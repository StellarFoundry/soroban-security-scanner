//! SS-041: authorization check inside a loop may not cover every iteration.

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, STORAGE_MUTATORS};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-041",
    title: "Authorization check inside a loop",
    description: "A contract entry point performs `require_auth` (or \
`require_auth_for_args`) inside a loop body in a position that does not clearly \
cover every iteration: the check is conditional, or it runs only after a \
state-changing operation. A single check in that position can leave later \
iterations or earlier side effects unauthorized. Unconditional checks at the top \
of a loop are ambiguous and are deliberately not reported by this rule.",
    category: Category::Authorization,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Authorize the actor before any state change and outside any \
conditional branch that can skip iterations, or authorize each distinct actor \
explicitly for every loop item with `require_auth_for_args`. Document intentional \
per-item authorization.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects authorization checks whose placement inside a loop is unsafe.
pub struct AuthorizationInLoop;

struct LoopFrame {
    kind: &'static str,
    line: usize,
    start: usize,
    branch_base: usize,
}

struct AuthFact {
    line: usize,
    column: usize,
    loop_kind: &'static str,
    loop_line: usize,
    reason: &'static str,
    text: String,
}

#[derive(Default)]
struct LoopAuthVisitor {
    loops: Vec<LoopFrame>,
    branch_depth: usize,
    side_effects: Vec<usize>,
    auths: Vec<AuthFact>,
}

impl LoopAuthVisitor {
    fn enter_loop(&mut self, kind: &'static str, line: usize, start: usize) -> LoopFrame {
        LoopFrame {
            kind,
            line,
            start,
            branch_base: self.branch_depth,
        }
    }

    fn record_side_effect(&mut self, node: &syn::ExprMethodCall) {
        let name = node.method.to_string();
        let receiver = node
            .receiver
            .to_token_stream()
            .to_string()
            .to_ascii_lowercase();
        let storage_mutation =
            STORAGE_MUTATORS.contains(&name.as_str()) && receiver.contains("storage");
        let cross_contract = matches!(
            name.as_str(),
            "transfer" | "transfer_from" | "invoke" | "invoke_contract" | "call"
        ) || receiver.contains("client");
        if self.loops.is_empty() {
            return;
        }
        if storage_mutation || cross_contract {
            self.side_effects.push(node.span().byte_range().start);
        }
    }
}

impl<'ast> Visit<'ast> for LoopAuthVisitor {
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.visit_expr(&node.expr);
        let span = node.span();
        let frame = self.enter_loop("for", span.start().line, span.byte_range().start);
        self.loops.push(frame);
        self.visit_block(&node.body);
        self.loops.pop();
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.visit_expr(&node.cond);
        let span = node.span();
        let frame = self.enter_loop("while", span.start().line, span.byte_range().start);
        self.loops.push(frame);
        self.visit_block(&node.body);
        self.loops.pop();
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        let span = node.span();
        let frame = self.enter_loop("loop", span.start().line, span.byte_range().start);
        self.loops.push(frame);
        self.visit_block(&node.body);
        self.loops.pop();
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.visit_expr(&node.cond);
        self.branch_depth += 1;
        self.visit_block(&node.then_branch);
        if let Some((_, else_branch)) = &node.else_branch {
            self.visit_expr(else_branch);
        }
        self.branch_depth -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.visit_expr(&node.expr);
        self.branch_depth += 1;
        for arm in &node.arms {
            self.visit_expr(&arm.body);
        }
        self.branch_depth -= 1;
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.record_side_effect(node);

        let name = node.method.to_string();
        if name == "require_auth" || name == "require_auth_for_args" {
            if let Some(frame) = self.loops.last() {
                let start = node.span().byte_range().start;
                let conditional = self.branch_depth > frame.branch_base;
                let after_side_effect = self
                    .side_effects
                    .iter()
                    .any(|effect| *effect >= frame.start && *effect < start);
                let reason = if conditional {
                    Some("is conditional, so iterations that skip the branch are not authorized")
                } else if after_side_effect {
                    Some("runs after a state-changing operation, so earlier side effects are unauthorized")
                } else {
                    None
                };
                if let Some(reason) = reason {
                    let span = node.span();
                    self.auths.push(AuthFact {
                        line: span.start().line,
                        column: span.start().column + 1,
                        loop_kind: frame.kind,
                        loop_line: frame.line,
                        reason,
                        text: truncate(&node.to_token_stream().to_string(), 160),
                    });
                }
            }
        }

        visit::visit_expr_method_call(self, node);
    }
}

impl Rule for AuthorizationInLoop {
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
                let mut visitor = LoopAuthVisitor::default();
                visitor.visit_block(func.block);
                for auth in visitor.auths {
                    let location = location_for(ctx, source, auth.line, auth.column);
                    let evidence = format!(
                        "`{}` inside `{}` loop at line {} in entry point `{}` {}; one check may \
                         not be sufficient: {}",
                        auth.text,
                        auth.loop_kind,
                        auth.loop_line,
                        func.name,
                        auth.reason,
                        auth.text
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
    fn flags_conditional_authorization_inside_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn batch(env: Env, admin: Address, recipients: Vec<Address>) {
                    for recipient in recipients.iter() {
                        if recipient != admin {
                            admin.require_auth();
                        }
                        let _ = (&env, recipient);
                    }
                }
            }
            "#,
            Box::new(AuthorizationInLoop),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-041");
        assert!(findings[0].evidence.contains("`for` loop"));
        assert!(findings[0].evidence.contains("conditional"));
    }

    #[test]
    fn flags_authorization_after_state_change_inside_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn batch(env: Env, admin: Address, recipients: Vec<Address>) {
                    for recipient in recipients.iter() {
                        env.storage().persistent().set(recipient, &1);
                        admin.require_auth();
                    }
                }
            }
            "#,
            Box::new(AuthorizationInLoop),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .contains("after a state-changing operation"));
    }

    #[test]
    fn does_not_flag_unconditional_authorization_at_loop_top() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn batch(env: Env, admin: Address, recipients: Vec<Address>) {
                    for recipient in recipients.iter() {
                        admin.require_auth();
                        let _ = (&env, recipient);
                    }
                }
            }
            "#,
            Box::new(AuthorizationInLoop),
        );
        assert!(
            findings.is_empty(),
            "ambiguous case must not fire: {findings:#?}"
        );
    }

    #[test]
    fn does_not_flag_hoisted_authorization() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn batch(env: Env, admin: Address, recipients: Vec<Address>) {
                    admin.require_auth();
                    for recipient in recipients.iter() {
                        env.storage().persistent().set(recipient, &1);
                    }
                }
            }
            "#,
            Box::new(AuthorizationInLoop),
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
                    env.storage().persistent().set(&admin, &1);
                }
            }
            "#,
            Box::new(AuthorizationInLoop),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_conditional_authorization_outside_a_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address, enabled: bool) {
                    if enabled {
                        admin.require_auth();
                    }
                    env.storage().persistent().set(&admin, &1);
                }
            }
            "#,
            Box::new(AuthorizationInLoop),
        );
        assert!(findings.is_empty());
    }
}
