//! SS-023: sensitive data published in a contract event.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Identifiers that strongly suggest confidential or secret material.
pub const SENSITIVE_EVENT_HINTS: &[&str] = &[
    "secret",
    "private_key",
    "privkey",
    "password",
    "passwd",
    "mnemonic",
    "preimage",
    "passphrase",
    "api_key",
    "secret_key",
];

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-023",
    title: "Sensitive data published in contract event",
    description: "A contract entry point publishes an event whose topic or \
payload references an identifier associated with secret material (such as \
`secret`, `private_key`, `password`, `mnemonic`, or `preimage`). Soroban \
contract events are public and permanently recorded in ledger metadata, \
exposing any emitted secret to all observers.",
    category: Category::Events,
    default_severity: Severity::Low,
    default_confidence: Confidence::Low,
    remediation: "Never emit raw secrets, preimages, or private keys in \
`env.events().publish(...)`. Emit a cryptographic commitment (such as a SHA-256 \
hash) or an opaque identifier instead.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/events"],
};

/// Detects `events().publish(...)` calls that reference secret-like identifiers.
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
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                for call in &facts.method_calls {
                    if call.name != "publish"
                        || !call.context.to_ascii_lowercase().contains("event")
                    {
                        continue;
                    }
                    let joined_args = call.args.join(" ").to_ascii_lowercase();
                    if let Some(matched) = SENSITIVE_EVENT_HINTS
                        .iter()
                        .find(|hint| joined_args.contains(**hint))
                    {
                        let location = location_for(ctx, source, call.line, call.column);
                        let evidence = format!(
                            "event payload in `{}` references sensitive identifier `{}`: {}",
                            func.name, matched, call.text
                        );
                        out.push(Finding::new(&METADATA, location, evidence));
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
    fn flags_secret_in_published_event() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Escrow {
                pub fn reveal(env: Env, caller: Address, secret_key: Bytes) {
                    caller.require_auth();
                    env.events().publish((symbol_short!("reveal"),), secret_key);
                }
            }
            "#,
            Box::new(SensitiveDataInEvents),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-023");
    }

    #[test]
    fn does_not_flag_public_commitment_event() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Escrow {
                pub fn commit(env: Env, caller: Address, commitment_hash: BytesN<32>) {
                    caller.require_auth();
                    env.events().publish((symbol_short!("commit"),), commitment_hash);
                }
            }
            "#,
            Box::new(SensitiveDataInEvents),
        );
        assert!(findings.is_empty());
    }
}
