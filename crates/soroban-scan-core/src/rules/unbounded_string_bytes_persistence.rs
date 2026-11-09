//! SS-025: unbounded `String` or `Bytes` parameter persisted to storage.

use std::collections::BTreeSet;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-025",
    title: "Unbounded String or Bytes parameter persisted to storage",
    description: "A public contract entry point accepts a dynamically sized \
`String` or `Bytes` parameter and writes it to persistent or instance storage \
without checking `.len()`. Storing unbounded variable-length payloads inflates \
ledger rent fees and can push entry size past Soroban host limits.",
    category: Category::ResourceUsage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Enforce an explicit maximum byte/character length on \
`String` and `Bytes` parameters (for example `if memo.len() > MAX_LEN { return \
Err(...); }`) before writing them to contract storage.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data"],
};

/// Detects unvalidated `String` or `Bytes` parameters written to storage.
pub struct UnboundedStringBytesPersistence;

fn is_unbounded_buf_type(ty: &str) -> bool {
    let trimmed = ty.trim().trim_start_matches('&').trim();
    if trimmed.contains("BytesN") {
        return false;
    }
    trimmed == "String"
        || trimmed == "Bytes"
        || trimmed.ends_with("::String")
        || trimmed.ends_with("::Bytes")
}

impl Rule for UnboundedStringBytesPersistence {
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
                let Some(summary) = source
                    .functions
                    .iter()
                    .find(|f| f.name == func.name && f.line == func.line)
                else {
                    continue;
                };
                let buf_params: BTreeSet<&str> = summary
                    .params
                    .iter()
                    .filter(|p| is_unbounded_buf_type(&p.ty))
                    .map(|p| p.name.as_str())
                    .collect();
                if buf_params.is_empty() {
                    continue;
                }

                let facts = facts_from_block_with_imports(func.block, &source.imports);
                for write in facts.storage_mutations() {
                    if write.name != "set" {
                        continue;
                    }
                    let val_arg = write.argument(1).unwrap_or(write.text.as_str());
                    let Some(param) = buf_params.iter().find(|p| {
                        val_arg
                            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                            .any(|tok| tok == **p)
                    }) else {
                        continue;
                    };
                    let has_len_check = facts.method_calls.iter().any(|m| {
                        m.start_byte < write.start_byte
                            && (m.name == "len" || m.name == "is_empty")
                            && m.context.contains(*param)
                    });
                    if has_len_check {
                        continue;
                    }
                    let location = location_for(ctx, source, write.line, write.column);
                    let evidence = format!(
                        "unbounded parameter `{}` persisted without length check in `{}`: {}",
                        param, func.name, write.text
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
    fn flags_unbounded_string_written_to_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Profile {
                pub fn set_bio(env: Env, user: Address, bio: String) {
                    user.require_auth();
                    env.storage().persistent().set(&user, &bio);
                }
            }
            "#,
            Box::new(UnboundedStringBytesPersistence),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-025");
    }

    #[test]
    fn does_not_flag_when_len_is_checked_or_bytesn_used() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Profile {
                pub fn set_bio(env: Env, user: Address, bio: String, hash: BytesN<32>) {
                    user.require_auth();
                    if bio.len() > 256 {
                        return;
                    }
                    env.storage().persistent().set(&user, &bio);
                    env.storage().persistent().set(&symbol_short!("HASH"), &hash);
                }
            }
            "#,
            Box::new(UnboundedStringBytesPersistence),
        );
        assert!(findings.is_empty());
    }
}
