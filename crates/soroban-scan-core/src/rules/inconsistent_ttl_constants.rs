//! SS-026: inconsistent or inverted TTL `threshold` and `extend_to` arguments.

use std::collections::BTreeMap;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{facts_from_file_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-026",
    title: "Inconsistent or inverted TTL threshold and extend_to arguments",
    description: "A call to `extend_ttl` passes a `threshold` larger than \
`extend_to` (or `extend_to == 0`). The Soroban host requires \
`threshold <= extend_to` and panics at runtime when the arguments are \
inverted.",
    category: Category::Storage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::High,
    remediation: "Ensure `threshold <= extend_to` and `extend_to > 0` in every \
`extend_ttl` call, and define named constants (`MIN_TTL_THRESHOLD` and \
`MAX_TTL_EXTEND`) in ascending order.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data"],
};

/// Detects `extend_ttl` calls where `threshold > extend_to` or `extend_to == 0`.
pub struct InconsistentTtlConstants;

fn parse_u64_expr(text: &str, consts: &BTreeMap<String, u64>) -> Option<u64> {
    let trimmed = text.trim();
    if let Some(&val) = consts.get(trimmed) {
        return Some(val);
    }
    let clean: String = trimmed.chars().filter(|c| *c != '_').collect();
    clean.parse::<u64>().ok()
}

impl Rule for InconsistentTtlConstants {
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
            let mut const_vals: BTreeMap<String, u64> = BTreeMap::new();
            for c in &source.constants {
                let clean: String = c.value.trim().chars().filter(|ch| *ch != '_').collect();
                if let Ok(v) = clean.parse::<u64>() {
                    const_vals.insert(c.name.clone(), v);
                    const_vals.insert(c.qualified_name.clone(), v);
                }
            }

            let facts = facts_from_file_with_imports(file, &source.imports);
            for call in facts.ttl_management() {
                if call.args.len() < 2 {
                    continue;
                }
                let threshold_arg = &call.args[call.args.len() - 2];
                let extend_to_arg = &call.args[call.args.len() - 1];
                let (Some(threshold), Some(extend_to)) = (
                    parse_u64_expr(threshold_arg, &const_vals),
                    parse_u64_expr(extend_to_arg, &const_vals),
                ) else {
                    continue;
                };
                if threshold > extend_to || extend_to == 0 {
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "invalid TTL parameters (`threshold` = {threshold}, `extend_to` = {extend_to}): {}",
                        call.text
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
    fn flags_inverted_ttl_literals() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn bump(env: Env, admin: Address) {
                    admin.require_auth();
                    env.storage().instance().extend_ttl(5000, 100);
                }
            }
            "#,
            Box::new(InconsistentTtlConstants),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-026");
    }

    #[test]
    fn flags_inverted_ttl_constants() {
        let findings = scan_rule(
            r#"
            const THRESHOLD: u32 = 10_000;
            const EXTEND_TO: u32 = 1_000;

            #[contractimpl]
            impl C {
                pub fn bump(env: Env, admin: Address) {
                    admin.require_auth();
                    env.storage().persistent().extend_ttl(&DataKey::Val, THRESHOLD, EXTEND_TO);
                }
            }
            "#,
            Box::new(InconsistentTtlConstants),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-026");
    }

    #[test]
    fn does_not_flag_valid_ttl_arguments() {
        let findings = scan_rule(
            r#"
            const THRESHOLD: u32 = 100;
            const EXTEND_TO: u32 = 1_000;

            #[contractimpl]
            impl C {
                pub fn bump(env: Env, admin: Address) {
                    admin.require_auth();
                    env.storage().persistent().extend_ttl(&DataKey::Val, THRESHOLD, EXTEND_TO);
                }
            }
            "#,
            Box::new(InconsistentTtlConstants),
        );
        assert!(findings.is_empty());
    }
}
