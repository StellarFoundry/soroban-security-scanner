//! SS-023: sensitive-looking data published in events.
//!
//! Ledger data is public forever, so publishing secrets or secret-like values in
//! an event is an irreversible disclosure. The detector is a pure name
//! heuristic over parameters and string literals and reports low confidence.

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
    id: "SS-023",
    title: "Sensitive-looking data published in events",
    description: "Events are public on the ledger forever. Publishing a value \
whose name suggests a secret (secret, key, seed, proof) risks an irreversible \
disclosure. This is a name-based heuristic over parameters and string literals \
and reports low confidence.",
    category: Category::Events,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Do not publish secrets or secret-derived values in events. \
Commit to a hash if you must prove knowledge, and keep key material, seeds, and \
preimages off-chain.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/events",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects event publishes of sensitive-looking parameters or literals.
pub struct SensitiveDataInEvents;

impl Rule for SensitiveDataInEvents {
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
                let sensitive_params: Vec<String> = func
                    .param_types
                    .iter()
                    .map(|(name, _)| name.clone())
                    .filter(|name| sensitive_identifier(name))
                    .collect();
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                for call in &facts.method_calls {
                    if call.name != "publish"
                        || !call.context.to_ascii_lowercase().contains("event")
                    {
                        continue;
                    }
                    let mut found: BTreeSet<String> = BTreeSet::new();
                    for arg in &call.args {
                        for param in &sensitive_params {
                            if contains_ident(arg, param) {
                                found.insert(format!("parameter `{param}`"));
                            }
                        }
                        for literal in string_literals(arg) {
                            if sensitive_identifier(&literal) {
                                found.insert(format!("literal `{literal}`"));
                            }
                        }
                    }
                    if found.is_empty() {
                        continue;
                    }
                    let location = location_for(ctx, source, call.line, call.column);
                    let values = found.into_iter().collect::<Vec<_>>().join(", ");
                    let evidence = format!(
                        "event publishes sensitive-looking {values} in entry point `{}`: {}",
                        func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

/// Whether an identifier or literal value name suggests secret material.
fn sensitive_identifier(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    const STRONG: &[&str] = &[
        "secret",
        "seed",
        "proof",
        "preimage",
        "mnemonic",
        "passphrase",
        "password",
        "privatekey",
    ];
    if STRONG.iter().any(|hint| lowered.contains(hint)) {
        return true;
    }
    if lowered == "key" || lowered == "keys" {
        return true;
    }
    lowered.contains("key")
        && ["private_", "secret_", "signing_", "seed_"]
            .iter()
            .any(|prefix| lowered.contains(prefix))
}

/// Whether `needle` appears in `haystack` as a whole identifier.
fn contains_ident(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(offset) = haystack[start..].find(needle) {
        let index = start + offset;
        let end = index + needle.len();
        let before = index == 0 || !is_ident_byte(bytes[index - 1]);
        let after = end >= bytes.len() || !is_ident_byte(bytes[end]);
        if before && after {
            return true;
        }
        start = end;
    }
    false
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Extracts the values of simple string literals from rendered source.
fn string_literals(text: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            continue;
        }
        let mut value = String::new();
        while let Some(inner) = chars.next() {
            match inner {
                '"' => break,
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        value.push(escaped);
                    }
                }
                other => value.push(other),
            }
        }
        literals.push(value);
    }
    literals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_secret_parameter_published() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn commit(env: Env, secret: Bytes) {
                    env.events().publish(symbol_short!("commit"), secret);
                }
            }
            "#,
            Box::new(SensitiveDataInEvents),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-023");
        assert!(findings[0].evidence.contains("parameter `secret`"));
    }

    #[test]
    fn flags_sensitive_literal_published() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn emit(env: Env) {
                    env.events().publish((symbol_short!("note"), "seed"), 0);
                }
            }
            "#,
            Box::new(SensitiveDataInEvents),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("literal `seed`"));
    }

    #[test]
    fn does_not_flag_benign_event_data() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
                    env.events().publish(symbol_short!("transfer"), (from, to, amount));
                }
            }
            "#,
            Box::new(SensitiveDataInEvents),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_public_key_named_parameter() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn register(env: Env, public_key: BytesN<32>) {
                    env.events().publish(symbol_short!("register"), public_key);
                }
            }
            "#,
            Box::new(SensitiveDataInEvents),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn emit(env: Env, secret: Bytes) {
                    env.events().publish(symbol_short!("commit"), secret);
                }
            }
            "#,
            Box::new(SensitiveDataInEvents),
        );
        assert!(findings.is_empty());
    }
}
