//! SS-010: privileged storage change without an event.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Storage-key substrings that usually identify privileged configuration.
pub const PRIVILEGED_KEY_HINTS: &[&str] = &[
    "admin",
    "owner",
    "pause",
    "param",
    "config",
    "fee",
    "oracle",
    "governor",
    "role",
    "authority",
    "operator",
    "treasury",
];

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-010",
    title: "Privileged state change without an event",
    description: "A contract entry point mutates a storage key that looks like \
privileged configuration (for example admin, owner, pause, params, fees, or \
oracle) without publishing an event. Off-chain indexers and users rely on events \
to observe critical changes; without one, the change is invisible to monitoring \
and incident response.",
    category: Category::Events,
    default_severity: Severity::Low,
    default_confidence: Confidence::Low,
    remediation: "Publish an event with `env.events().publish(...)` for every \
privileged state change, including the old and new values where practical. Keep \
the event schema stable so indexers can rely on it.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/events"],
    deprecated: false,
};

/// Detects privileged storage mutations without an event.
pub struct MissingEvents;

impl Rule for MissingEvents {
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
                let publishes_event = facts.method_calls.iter().any(|call| {
                    call.name == "publish" && call.context.to_ascii_lowercase().contains("event")
                });
                if publishes_event {
                    continue;
                }
                for mutation in facts.storage_mutations() {
                    if !mentions_privileged_key(&mutation.text) {
                        continue;
                    }
                    let location = location_for(ctx, source, mutation.line, mutation.column);
                    let evidence = format!(
                        "privileged storage change without an event in `{}`: {}",
                        func.name, mutation.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

fn mentions_privileged_key(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    PRIVILEGED_KEY_HINTS.iter().any(|hint| lower.contains(hint))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_privileged_write_without_event() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_admin(env: Env, admin: Address) {
                    env.storage().persistent().set(&DataKey::Admin, &admin);
                }
            }
            "#,
            Box::new(MissingEvents),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-010");
        assert!(findings[0].evidence.contains("without an event"));
    }

    #[test]
    fn does_not_flag_when_event_is_published() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_admin(env: Env, admin: Address) {
                    env.storage().persistent().set(&DataKey::Admin, &admin);
                    env.events().publish((symbol_short!("admin"),), admin);
                }
            }
            "#,
            Box::new(MissingEvents),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_non_privileged_keys() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn put(env: Env, value: u32) {
                    env.storage().persistent().set(&DataKey::Value, &value);
                }
            }
            "#,
            Box::new(MissingEvents),
        );
        assert!(findings.is_empty());
    }
}
