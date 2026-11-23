//! SS-016: unbounded data stored in instance storage.

use std::collections::BTreeSet;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, CallFact};
use crate::analysis::storage::map_storage_accesses;
use crate::source::ParsedSource;

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-016",
    title: "Unbounded data stored in instance storage",
    description: "Instance storage is loaded for every invocation and has \
strict size limits. Writing repeated distinct keys, or growing a collection, in \
instance storage increases the cost of every call and can break the contract at \
scale. Constant configuration is a better fit for instance storage.",
    category: Category::Storage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Keep instance storage for small, fixed configuration. Store \
growing collections in persistent storage, and bound their size explicitly.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data"],
};

/// Detects repeated instance-storage keys and collection growth.
pub struct InstanceStorageForUnboundedData;

impl Rule for InstanceStorageForUnboundedData {
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
                let map_accesses = map_storage_accesses(func.block);
                let mut instance_sets: Vec<(&CallFact, Option<&str>)> = Vec::new();
                for call in &facts.method_calls {
                    if call.name == "set" && is_instance(source, &call.context) {
                        instance_sets.push((call, call.args.first().map(String::as_str)));
                    }
                }
                // UFCS calls (`Store::set(&store, key, value)`) carry the
                // storage handle as their first argument, so the key is the
                // penultimate one.
                for call in &facts.function_calls {
                    if call.name == "set" && is_instance(source, &call.context) {
                        let key = call
                            .args
                            .len()
                            .checked_sub(2)
                            .and_then(|index| call.args.get(index))
                            .map(String::as_str);
                        instance_sets.push((call, key));
                    }
                }

                let distinct_keys: BTreeSet<&str> =
                    instance_sets.iter().filter_map(|(_, key)| *key).collect();
                if instance_sets.len() >= 2 && distinct_keys.len() >= 2 {
                    for (call, _) in instance_sets {
                        let location = location_for(ctx, source, call.line, call.column);
                        let evidence = format!(
                            "repeated instance-storage keys in `{}`: {}",
                            func.name, call.text
                        );
                        out.push(Finding::new(&METADATA, location, evidence));
                    }
                    continue;
                }

                let reads_instance = facts
                    .method_calls
                    .iter()
                    .chain(facts.function_calls.iter())
                    .any(|call| call.name == "get" && is_instance(source, &call.context));
                if !reads_instance {
                    continue;
                }
                for growth in facts.method_calls.iter().filter(|call| {
                    matches!(call.name.as_str(), "push" | "push_back" | "push_front")
                }) {
                    let location = location_for(ctx, source, growth.line, growth.column);
                    let mut evidence = format!(
                        "unbounded collection growth in instance storage in `{}`: {}",
                        func.name, growth.text
                    );
                    // Key types are data from the map analysis. An unknown key
                    // is stated as unknown, never assumed bounded.
                    if let Some(map) = map_accesses
                        .iter()
                        .find(|access| access.key_type.is_unknown())
                    {
                        evidence.push_str(&format!(
                            "; stored map key type is unknown (map access at line {})",
                            map.line
                        ));
                    }
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

/// Whether a rendered call context resolves to instance storage.
///
/// The import map is consulted explicitly so aliases and glob imports are
/// canonicalized instead of compared as literal text.
fn is_instance(source: &ParsedSource, context: &str) -> bool {
    if context.to_ascii_lowercase().contains("instance") {
        return true;
    }
    source
        .resolve_path(context)
        .any_candidate(|path| path.to_ascii_lowercase().contains("instance"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_repeated_distinct_instance_keys() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn configure(env: Env, a: u32, b: u32) {
                    env.storage().instance().set(&DataKey::A, &a);
                    env.storage().instance().set(&DataKey::B, &b);
                }
            }
            "#,
            Box::new(InstanceStorageForUnboundedData),
        );
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].rule_id, "SS-016");
    }

    #[test]
    fn does_not_flag_single_instance_write() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn configure(env: Env, a: u32) {
                    env.storage().instance().set(&DataKey::A, &a);
                }
            }
            "#,
            Box::new(InstanceStorageForUnboundedData),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_persistent_storage() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn configure(env: Env, a: u32, b: u32) {
                    env.storage().persistent().set(&DataKey::A, &a);
                    env.storage().persistent().set(&DataKey::B, &b);
                }
            }
            "#,
            Box::new(InstanceStorageForUnboundedData),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_aliased_instance_storage_calls() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::storage::Instance as Store;

            #[contractimpl]
            impl C {
                pub fn configure(env: Env, a: u32, b: u32) {
                    let store = env.storage().instance();
                    Store::set(&store, &DataKey::A, &a);
                    Store::set(&store, &DataKey::B, &b);
                }
            }
            "#,
            Box::new(InstanceStorageForUnboundedData),
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn flags_glob_imported_instance_storage_calls() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::storage::*;

            #[contractimpl]
            impl C {
                pub fn configure(env: Env, a: u32, b: u32) {
                    let store = env.storage().instance();
                    Instance::set(&store, &DataKey::A, &a);
                    Instance::set(&store, &DataKey::B, &b);
                }
            }
            "#,
            Box::new(InstanceStorageForUnboundedData),
        );
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn does_not_flag_an_alias_to_persistent_storage() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::storage::Persistent as Store;

            #[contractimpl]
            impl C {
                pub fn configure(env: Env, a: u32, b: u32) {
                    let store = env.storage().persistent();
                    Store::set(&store, &DataKey::A, &a);
                    Store::set(&store, &DataKey::B, &b);
                }
            }
            "#,
            Box::new(InstanceStorageForUnboundedData),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn reports_unknown_map_key_type_in_evidence() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Env, Map};

            #[contractimpl]
            impl C {
                pub fn add(env: Env, value: u64) {
                    let map: Map<_, u64> = env.storage().instance().get(&Key::Items).unwrap();
                    map.push_back(value);
                    let _ = map;
                }
            }
            "#,
            Box::new(InstanceStorageForUnboundedData),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("map key type is unknown"));
    }
}
