//! SS-021: durable data written to temporary storage.
//!
//! Temporary-storage entries are removed when their TTL lapses. Writing data
//! that is meant to persist (configuration, balances, ownership) to temporary
//! storage can make it silently disappear. The detector is a key-name heuristic
//! and reports low confidence.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, CallFact};
use crate::source::ParsedSource;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-021",
    title: "Durable data written to temporary storage",
    description: "Temporary storage entries are removed when their TTL lapses, \
so data written there can silently disappear. Keys that look like configuration, \
balances, or ownership are strong hints that the value is meant to persist. This \
is a key-name heuristic and reports low confidence.",
    category: Category::Storage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Write durable state to persistent (or instance) storage. Use \
temporary storage only for data that may safely be discarded, and extend its TTL \
when it is still needed.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data",
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival",
    ],
};

/// Detects writes of durable-looking keys to temporary storage.
pub struct TemporaryStorageForDurableState;

/// Key-name fragments that suggest a value is meant to persist.
const DURABLE_KEY_HINTS: &[&str] = &[
    "config",
    "setting",
    "owner",
    "admin",
    "authority",
    "role",
    "balance",
    "supply",
    "allowance",
    "approval",
    "treasury",
    "reserve",
    "metadata",
    "decimal",
    "total",
    "symbol",
];

impl Rule for TemporaryStorageForDurableState {
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
                let facts = ctx.facts_for_function(source, &func);

                // `env.storage().temporary().set(key, value)`.
                for call in &facts.method_calls {
                    if call.name != "set" || !is_temporary(source, &call.context) {
                        continue;
                    }
                    if let Some(key) = call.args.first() {
                        report_if_durable(ctx, source, out, &func.name, call, key);
                    }
                }

                // UFCS form: `Temporary::set(&store, key, value)`.
                for call in &facts.function_calls {
                    if call.name != "set" || !is_temporary(source, &call.context) {
                        continue;
                    }
                    let key = call
                        .args
                        .len()
                        .checked_sub(2)
                        .and_then(|index| call.args.get(index));
                    if let Some(key) = key {
                        report_if_durable(ctx, source, out, &func.name, call, key);
                    }
                }
            }
        }
    }
}

fn report_if_durable(
    ctx: &AnalysisContext<'_>,
    source: &ParsedSource,
    out: &mut Vec<Finding>,
    function: &str,
    call: &CallFact,
    key: &str,
) {
    if !looks_like_durable_key(key) {
        return;
    }
    let location = location_for(ctx, source, call.line, call.column);
    let evidence = format!(
        "durable-looking key written to temporary storage in `{function}`: {}",
        call.text
    );
    out.push(Finding::new(&METADATA, location, evidence));
}

/// Whether a rendered key expression mentions a durable-state concept.
fn looks_like_durable_key(key: &str) -> bool {
    let lowered = key.to_ascii_lowercase();
    DURABLE_KEY_HINTS.iter().any(|hint| lowered.contains(hint))
}

/// Whether a rendered call context resolves to temporary storage.
fn is_temporary(source: &ParsedSource, context: &str) -> bool {
    if context.to_ascii_lowercase().contains("temporary") {
        return true;
    }
    source
        .resolve_path(context)
        .any_candidate(|path| path.to_ascii_lowercase().contains("temporary"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_owner_written_to_temporary_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_owner(env: Env, owner: Address) {
                    env.storage().temporary().set(&DataKey::Owner, &owner);
                }
            }
            "#,
            Box::new(TemporaryStorageForDurableState),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-021");
    }

    #[test]
    fn flags_ufcs_temporary_storage_write() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::storage::Temporary as Store;

            #[contractimpl]
            impl C {
                pub fn set_balance(env: Env, amount: i128) {
                    let store = env.storage().temporary();
                    Store::set(&store, &DataKey::Balance, &amount);
                }
            }
            "#,
            Box::new(TemporaryStorageForDurableState),
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_ephemeral_keys() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn cache(env: Env, value: u32) {
                    env.storage().temporary().set(&DataKey::Session, &value);
                }
            }
            "#,
            Box::new(TemporaryStorageForDurableState),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_persistent_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_owner(env: Env, owner: Address) {
                    env.storage().persistent().set(&DataKey::Owner, &owner);
                }
            }
            "#,
            Box::new(TemporaryStorageForDurableState),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn set_owner(env: Env, owner: Address) {
                    env.storage().temporary().set(&DataKey::Owner, &owner);
                }
            }
            "#,
            Box::new(TemporaryStorageForDurableState),
        );
        assert!(findings.is_empty());
    }
}
