//! SS-007: hardcoded Stellar account or contract address.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{location_for, looks_like_stellar_address};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-007",
    title: "Hardcoded Stellar account or contract address",
    description: "A string literal in the contract matches the shape of a \
Stellar account (`G...`) or contract (`C...`) address. Hardcoding an address \
bakes a fixed counterparty or administrator into the contract, preventing \
rotation and making the contract unsafe if that key or contract changes or is \
compromised. Addresses are public, so this is a design concern rather than a \
secret leak.",
    category: Category::Configuration,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Store addresses in contract storage or pass them as \
parameters, and validate them against stored configuration. If an address must \
be a compile-time constant, document the operational plan for rotation and key \
compromise.",
    references: &["https://developers.stellar.org/docs/learn/encyclopedia/security"],
};

/// Detects hardcoded Stellar strkeys in contract source.
pub struct HardcodedAddress;

impl Rule for HardcodedAddress {
    fn metadata(&self) -> &RuleMetadata {
        &METADATA
    }

    fn analyze(&self, ctx: &AnalysisContext<'_>, out: &mut Vec<Finding>) {
        if !ctx.is_confirmed_soroban() {
            return;
        }
        for source in ctx.sources() {
            if source.syntax.is_none() {
                continue;
            }
            let facts = ctx.facts_for_source(source);
            for literal in &facts.strings {
                if !looks_like_stellar_address(&literal.value) {
                    continue;
                }
                let location = location_for(ctx, source, literal.line, literal.column);
                let evidence = format!("hardcoded Stellar address literal: {}", literal.value);
                out.push(Finding::new(&METADATA, location, evidence));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_hardcoded_account_address() {
        let addr = format!("G{}", "A".repeat(55));
        let src =
            format!("#[contractimpl]\nimpl C {{ pub fn f() -> &'static str {{ \"{addr}\" }} }}\n");
        let findings = scan_rule(&src, Box::new(HardcodedAddress));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-007");
    }

    #[test]
    fn ignores_ordinary_strings() {
        let findings = scan_rule(
            "#[contractimpl]\nimpl C { pub fn f() -> &'static str { \"hello\" } }\n",
            Box::new(HardcodedAddress),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn ignores_near_miss_string() {
        let addr = format!("X{}", "A".repeat(55));
        let src =
            format!("#[contractimpl]\nimpl C {{ pub fn f() -> &'static str {{ \"{addr}\" }} }}\n");
        let findings = scan_rule(&src, Box::new(HardcodedAddress));
        assert!(findings.is_empty());
    }
}
