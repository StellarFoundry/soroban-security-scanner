//! SS-020: unvalidated XDR or Bytes deserialization.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-020",
    title: "Unvalidated XDR or Bytes deserialization",
    description: "A public contract entry point deserializes an untrusted \
parameter via `from_xdr` without first bounding its byte length or validating \
the payload. Unbounded XDR deserialization on attacker-controlled `Bytes` can \
exhaust Soroban CPU/memory budgets or panic on malformed input.",
    category: Category::ResourceUsage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Validate the input `Bytes` length against an explicit upper \
bound (for example `if payload.len() > MAX_XDR_BYTES { return Err(...); }`) \
before calling `from_xdr`, and handle deserialization errors gracefully.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security"],
};

/// Detects `from_xdr` calls on unvalidated entry-point parameters.
pub struct UnvalidatedXdrDeserialization;

impl Rule for UnvalidatedXdrDeserialization {
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
                if !func.is_public || func.params.is_empty() {
                    continue;
                }
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                let deserialize_calls = facts
                    .function_calls
                    .iter()
                    .chain(facts.method_calls.iter())
                    .filter(|call| call.name == "from_xdr");

                for call in deserialize_calls {
                    let mentioned_param = func.params.iter().find(|param| {
                        param.as_str() != "env"
                            && (call.text.contains(param.as_str())
                                || call.args.iter().any(|arg| arg.contains(param.as_str())))
                    });
                    let Some(param) = mentioned_param else {
                        continue;
                    };
                    let has_len_guard = facts.method_calls.iter().any(|m| {
                        m.start_byte < call.start_byte
                            && (m.name == "len" || m.name == "is_empty" || m.name == "slice")
                            && m.context.contains(param.as_str())
                    }) || facts.comparisons.iter().any(|cmp| {
                        cmp.line <= call.line && cmp.text.contains(param.as_str())
                    });
                    if has_len_guard {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "unbounded `from_xdr` deserialization of parameter `{}` in `{}`: {}",
                        param, func.name, call.text
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
    fn flags_unbounded_from_xdr_on_parameter() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Decoder {
                pub fn decode(env: Env, caller: Address, payload: Bytes) -> u64 {
                    caller.require_auth();
                    u64::from_xdr(&env, &payload).unwrap_or(0)
                }
            }
            "#,
            Box::new(UnvalidatedXdrDeserialization),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-020");
    }

    #[test]
    fn does_not_flag_when_length_is_bounded() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Decoder {
                pub fn decode(env: Env, caller: Address, payload: Bytes) -> u64 {
                    caller.require_auth();
                    if payload.len() > 64 {
                        return 0;
                    }
                    u64::from_xdr(&env, &payload).unwrap_or(0)
                }
            }
            "#,
            Box::new(UnvalidatedXdrDeserialization),
        );
        assert!(findings.is_empty());
    }
}
