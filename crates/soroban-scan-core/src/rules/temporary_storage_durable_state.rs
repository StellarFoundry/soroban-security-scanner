//! SS-021: durable state stored in temporary storage.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Key substrings that strongly indicate durable contract state.
pub const DURABLE_KEY_HINTS: &[&str] = &[
    "admin",
    "owner",
    "balance",
    "total_supply",
    "allowance",
    "reserve",
    "treasury",
    "governor",
    "stake",
];

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-021",
    title: "Durable state stored in temporary storage",
    description: "A contract entry point writes a key that represents durable \
state (such as admin, owner, balance, allowance, or reserve) into \
`storage().temporary()`. Temporary storage entries are permanently deleted \
when their TTL expires and cannot be restored from the ledger archive, which \
can brick access control or erase user balances.",
    category: Category::Storage,
    default_severity: Severity::High,
    default_confidence: Confidence::Medium,
    remediation: "Store administrative configuration in `storage().instance()` \
or `storage().persistent()`, and store per-user balances, allowances, and \
positions in `storage().persistent()` so they can be restored if archived.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data"],
};

/// Detects writes of durable state keys to `storage().temporary()`.
pub struct TemporaryStorageDurableState;

impl Rule for TemporaryStorageDurableState {
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
                for call in &facts.method_calls {
                    if (call.name == "set" || call.name == "update")
                        && call.context.to_ascii_lowercase().contains("temporary")
                    {
                        let key_text = call.argument(0).unwrap_or(call.text.as_str());
                        let lower = key_text.to_ascii_lowercase();
                        if DURABLE_KEY_HINTS.iter().any(|hint| lower.contains(hint)) {
                            let location = location_for(ctx, source, call.line, call.column);
                            let evidence = format!(
                                "durable state key `{}` written to temporary storage in `{}`: {}",
                                key_text, func.name, call.text
                            );
                            out.push(Finding::new(&METADATA, location, evidence));
                        }
                    }
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
    fn flags_durable_key_in_temporary_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Token {
                pub fn set_balance(env: Env, admin: Address, amount: i128) {
                    admin.require_auth();
                    env.storage().temporary().set(&DataKey::Balance, &amount);
                }
            }
            "#,
            Box::new(TemporaryStorageDurableState),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-021");
    }

    #[test]
    fn does_not_flag_ephemeral_key_or_persistent_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Token {
                pub fn cache_price(env: Env, admin: Address, price: i128) {
                    admin.require_auth();
                    env.storage().temporary().set(&DataKey::CachedQuote, &price);
                    env.storage().persistent().set(&DataKey::Balance, &price);
                }
            }
            "#,
            Box::new(TemporaryStorageDurableState),
        );
        assert!(findings.is_empty());
    }
}
