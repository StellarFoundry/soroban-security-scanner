//! SS-042: security check unreachable on every path.

use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::analysis::cfg::{ControlFlowGraph, NodeKind, Reachability};
use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, ContractFn};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-042",
    title: "Security check unreachable on every path",
    description: "A caller-authorization or validation check appears after a \
statement that always leaves the function, such as an unconditional `return`. \
No execution path reaches the check, so it provides a false sense of protection \
while the actual behaviour is unguarded. The detector reports only when the \
function's control-flow graph is complete: a truncated graph or one containing \
constructs the builder does not model suppresses the finding.",
    category: Category::Authorization,
    default_severity: Severity::Low,
    default_confidence: Confidence::Medium,
    remediation: "Remove the dead check or move it before the early return so \
every path that performs the sensitive operation is guarded. If the early return \
is intentional, make the guard part of the condition that returns instead of \
leaving unreachable code behind.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://doc.rust-lang.org/reference/statements.html#unreachable-code",
    ],
};

/// Detects authorization and validation checks the CFG can never reach.
pub struct UnreachableSecurityCheck;

/// Call names treated as security checks.
///
/// The list is deliberately explicit. `validate_`, `verify_`, `check_`, and
/// `ensure_` prefixes cover the documented validation-helper naming convention;
/// other helpers are not guessed. Macro checks (`assert!`, `panic!`) are not
/// included because the CFG models macros as `Unknown` nodes, which suppress
/// this rule by design.
const CHECK_NAMES: &[&str] = &["require_auth", "require_auth_for_args"];
const CHECK_PREFIXES: &[&str] = &["validate_", "verify_", "check_", "ensure_"];

fn is_check(name: &str) -> bool {
    CHECK_NAMES.contains(&name) || CHECK_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

struct CheckSite {
    name: String,
    line: usize,
    column: usize,
}

#[derive(Default)]
struct CheckVisitor {
    checks: Vec<CheckSite>,
}

impl CheckVisitor {
    fn push(&mut self, name: &str, node_span: proc_macro2::Span) {
        let start = node_span.start();
        self.checks.push(CheckSite {
            name: name.to_string(),
            line: start.line,
            column: start.column + 1,
        });
    }
}

impl<'ast> Visit<'ast> for CheckVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if is_check(&name) {
            self.push(&name, node.span());
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            if let Some(segment) = path.path.segments.last() {
                let name = segment.ident.to_string();
                if is_check(&name) {
                    self.push(&name, node.span());
                }
            }
        }
        visit::visit_expr_call(self, node);
    }
}

impl Rule for UnreachableSecurityCheck {
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
                let graph = ctx.cfg_for_function(source, &func);
                if !graph.is_complete() {
                    // An incomplete graph cannot prove unreachability. Record
                    // nothing instead of guessing.
                    continue;
                }
                let mut visitor = CheckVisitor::default();
                visitor.visit_block(func.block);
                for check in visitor.checks {
                    if graph.reachability_at(check.line) != Reachability::Unreachable {
                        continue;
                    }
                    let location = location_for(ctx, source, check.line, check.column);
                    out.push(Finding::new(
                        &METADATA,
                        location,
                        evidence(&check, &func, &graph),
                    ));
                }
            }
        }
    }
}

fn evidence(check: &CheckSite, func: &ContractFn<'_>, graph: &ControlFlowGraph) -> String {
    let nearest_return = graph
        .nodes
        .iter()
        .filter(|node| node.kind == NodeKind::Return && node.span.line <= check.line)
        .map(|node| node.span.line)
        .max();
    let because = match nearest_return {
        Some(line) => {
            format!("every path leaves the function first (nearest `return` at line {line})")
        }
        None => "no path from the function entry reaches it".to_string(),
    };
    format!(
        "`{}` check at line {} in `{}` is unreachable: {}; \
         CFG is complete ({} nodes, {} edges, no unknown nodes)",
        check.name,
        check.line,
        func.name,
        because,
        graph.nodes.len(),
        graph.edges.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_check_after_unconditional_return() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address) {
                    return;
                    admin.require_auth();
                    env.storage().persistent().set(&admin, &1);
                }
            }
            "#,
            Box::new(UnreachableSecurityCheck),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-042");
        assert!(findings[0].evidence.contains("unreachable"));
        assert!(findings[0].evidence.contains("nearest `return`"));
    }

    #[test]
    fn flags_check_after_return_inside_a_branch() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address, stop: bool) {
                    if stop {
                        return;
                        admin.require_auth();
                    }
                    validate_amount(&env, 1);
                }
            }
            "#,
            Box::new(UnreachableSecurityCheck),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("`require_auth`"));
    }

    #[test]
    fn does_not_flag_a_reachable_check() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address, stop: bool) {
                    admin.require_auth();
                    if stop {
                        return;
                    }
                    validate_amount(&env, 1);
                }
            }
            "#,
            Box::new(UnreachableSecurityCheck),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn suppresses_findings_when_the_cfg_is_incomplete() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address) {
                    return;
                    admin.require_auth();
                    unknown_macro!();
                }
            }
            "#,
            Box::new(UnreachableSecurityCheck),
        );
        assert!(
            findings.is_empty(),
            "an unknown construct must suppress the finding: {findings:#?}"
        );
    }

    #[test]
    fn ignores_checks_in_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(env: Env, admin: Address) {
                    env.storage().persistent().set(&admin, &1);
                }
                fn dead(admin: Address) {
                    return;
                    admin.require_auth();
                }
            }
            "#,
            Box::new(UnreachableSecurityCheck),
        );
        assert!(findings.is_empty());
    }
}
