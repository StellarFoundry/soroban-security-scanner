//! SS-027: `current_contract_address()` used as `require_auth` subject.

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

use super::util::{contract_entry_functions, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-027",
    title: "current_contract_address() used as require_auth subject",
    description: "A contract entry point calls `require_auth` or \
`require_auth_for_args` on `env.current_contract_address()` (either directly \
or through a local binding). In the Soroban host, the currently executing \
contract is implicitly authorized for its own frame, so this check succeeds \
unconditionally and provides zero caller access control.",
    category: Category::Authorization,
    default_severity: Severity::High,
    default_confidence: Confidence::High,
    remediation: "Call `require_auth()` on the external caller or stored \
administrator `Address` that must approve the invocation, never on \
`env.current_contract_address()`.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security/authorization"],
};

/// Detects `require_auth` invoked on `env.current_contract_address()`.
pub struct CurrentContractAuthSubject;

#[derive(Default)]
struct SelfAuthVisitor {
    self_addr_vars: BTreeSet<String>,
    hits: Vec<(usize, usize, String)>,
}

fn is_current_contract_address_expr(expr: &syn::Expr) -> bool {
    expr.to_token_stream()
        .to_string()
        .contains("current_contract_address")
}

impl<'ast> Visit<'ast> for SelfAuthVisitor {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(pat), Some(init)) = (&node.pat, &node.init) {
            if is_current_contract_address_expr(&init.expr) {
                self.self_addr_vars.insert(pat.ident.to_string());
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        if method == "require_auth" || method == "require_auth_for_args" {
            let receiver_is_self = is_current_contract_address_expr(&node.receiver)
                || match &*node.receiver {
                    syn::Expr::Path(path) if path.path.segments.len() == 1 => {
                        let ident = path.path.segments[0].ident.to_string();
                        self.self_addr_vars.contains(&ident)
                    }
                    _ => false,
                };
            if receiver_is_self {
                let start = node.span().start();
                self.hits.push((
                    start.line,
                    start.column + 1,
                    node.to_token_stream().to_string(),
                ));
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

impl Rule for CurrentContractAuthSubject {
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
                let mut visitor = SelfAuthVisitor::default();
                visitor.visit_block(func.block);
                for (line, column, text) in visitor.hits {
                    let location = location_for(ctx, source, line, column);
                    let evidence = format!(
                        "`current_contract_address()` used as authorization subject in `{}`: {}",
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
    fn flags_direct_and_aliased_self_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn sweep(env: Env) {
                    env.current_contract_address().require_auth();
                    let me = env.current_contract_address();
                    me.require_auth();
                }
            }
            "#,
            Box::new(CurrentContractAuthSubject),
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "SS-027");
    }

    #[test]
    fn does_not_flag_external_caller_auth() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn sweep(env: Env, admin: Address) -> Address {
                    admin.require_auth();
                    env.current_contract_address()
                }
            }
            "#,
            Box::new(CurrentContractAuthSubject),
        );
        assert!(findings.is_empty());
    }
}
