//! SS-032: redundant `require_auth` call inside a loop body.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-032",
    title: "Redundant require_auth call inside a loop",
    description: "A contract entry point invokes `require_auth` or \
`require_auth_for_args` inside a `for`, `while`, or `loop` body. Repeating \
authorization on every iteration wastes Soroban CPU/host-call budget and \
typically indicates that caller authorization should be hoisted before the \
loop and bound to the full batch of arguments once.",
    category: Category::ResourceUsage,
    default_severity: Severity::Low,
    default_confidence: Confidence::Low,
    remediation: "Hoist `require_auth()` or `require_auth_for_args(...)` out \
of the loop so caller authorization is verified once before iterating. When \
authorizing distinct addresses supplied in a batch, deduplicate the addresses \
or validate batch size before invoking `require_auth`.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/security/authorization",
        "https://developers.stellar.org/docs/learn/fundamentals/fees-resource-limits-metering",
    ],
};

/// Detects `require_auth` / `require_auth_for_args` calls lexically inside loop bodies.
pub struct RequireAuthInLoop;

impl Rule for RequireAuthInLoop {
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
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                for call in facts.loop_require_auth_calls() {
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "`{}` invoked inside loop body in `{}`: {}",
                        call.name, func.name, call.text
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
    fn flags_require_auth_in_for_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl BatchPay {
                pub fn distribute(env: Env, admin: Address, recipients: Vec<Address>) {
                    for recipient in recipients.iter() {
                        admin.require_auth();
                        env.storage().persistent().set(&recipient, &100_i128);
                    }
                }
            }
            "#,
            Box::new(RequireAuthInLoop),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-032");
        assert!(findings[0].evidence.contains("inside loop body"));
    }

    #[test]
    fn flags_require_auth_for_args_in_while_and_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl BatchPay {
                pub fn process(env: Env, admin: Address, count: u32) {
                    let mut i = 0;
                    while i < count {
                        admin.require_auth_for_args((&count,).into_val(&env));
                        i += 1;
                    }
                    loop {
                        admin.require_auth();
                        break;
                    }
                }
            }
            "#,
            Box::new(RequireAuthInLoop),
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn does_not_flag_hoisted_require_auth_before_loop() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl BatchPay {
                pub fn distribute(env: Env, admin: Address, recipients: Vec<Address>) {
                    admin.require_auth();
                    for recipient in recipients.iter() {
                        env.storage().persistent().set(&recipient, &100_i128);
                    }
                }
            }
            "#,
            Box::new(RequireAuthInLoop),
        );
        assert!(findings.is_empty());
    }
}
