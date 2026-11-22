//! SS-026: TTL constants outside the documented expected range.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{location_for, CallFact};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-026",
    title: "TTL constant outside the expected range",
    description: "A storage `extend_ttl` or `set_ttl` call uses an integer \
literal outside the documented expected range of TTL ledgers. A zero or very \
small TTL expires entries almost immediately, while a value above the network \
maximum is rejected or signals a unit mistake (for example seconds instead of \
ledgers). Either case can cause lost data or unexpected transaction failures. \
The detector only inspects literal constants, not computed expressions.",
    category: Category::ResourceUsage,
    default_severity: Severity::Low,
    default_confidence: Confidence::Low,
    remediation: "Define named TTL constants based on the contract's retention \
policy and the Soroban network maximum (about six months of ledgers), then pass \
those constants to `extend_ttl`/`set_ttl`. Use the same policy for every key so \
entries expire predictably instead of using ad-hoc literals.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data",
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/state-archival",
    ],
};

/// Smallest TTL the detector treats as meaningful, in ledgers.
pub const MIN_TTL_LEDGERS: u64 = 1;

/// Largest expected TTL, in ledgers: the network cap of about six months
/// (180 days at 5 seconds per ledger).
pub const MAX_TTL_LEDGERS: u64 = 3_110_400;

/// Detects out-of-range literal TTL constants.
pub struct InconsistentTtlConstants;

impl Rule for InconsistentTtlConstants {
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
            for call in &facts.method_calls {
                let arguments: &[(&str, usize)] = match call.name.as_str() {
                    "extend_ttl" => &[("threshold", 1), ("bump", 2)],
                    "set_ttl" => &[("ttl", 1)],
                    _ => continue,
                };
                let out_of_range = out_of_range_values(call, arguments);
                if out_of_range.is_empty() {
                    continue;
                }
                let location = location_for(ctx, source, call.line, call.column);
                let evidence = format!(
                    "TTL constant(s) outside the expected range \
                     {MIN_TTL_LEDGERS}..={MAX_TTL_LEDGERS} ledgers in `{}`: {}",
                    call.name,
                    out_of_range.join(", ")
                );
                out.push(Finding::new(&METADATA, location, evidence));
            }
        }
    }
}

fn out_of_range_values(call: &CallFact, arguments: &[(&str, usize)]) -> Vec<String> {
    let mut values = Vec::new();
    for (label, index) in arguments {
        let Some(argument) = call.argument(*index) else {
            continue;
        };
        let Some(value) = parse_ttl_literal(argument) else {
            continue;
        };
        if !(MIN_TTL_LEDGERS..=MAX_TTL_LEDGERS).contains(&value) {
            values.push(format!("{label}={value}"));
        }
    }
    values
}

/// Parses a plain integer literal, tolerating `_` separators and type suffixes.
fn parse_ttl_literal(text: &str) -> Option<u64> {
    let mut value = text.trim();
    for suffix in [
        "usize", "isize", "u128", "i128", "u64", "i64", "u32", "i32", "u16", "i16", "u8", "i8",
    ] {
        if let Some(stripped) = value.strip_suffix(suffix) {
            value = stripped.trim_end_matches('_');
            break;
        }
    }
    let digits: String = value
        .chars()
        .filter(|character| *character != '_')
        .collect();
    if digits.is_empty() || !digits.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_zero_and_out_of_range_ttl_literals() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn put(env: Env, admin: Address, key: Symbol, value: u32) {
                    admin.require_auth();
                    env.storage().persistent().set(&key, &value);
                    env.storage().persistent().extend_ttl(&key, 0, 9_999_999);
                }
            }
            "#,
            Box::new(InconsistentTtlConstants),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-026");
        assert!(findings[0].evidence.contains("threshold=0"));
        assert!(findings[0].evidence.contains("bump=9999999"));
    }

    #[test]
    fn flags_single_out_of_range_set_ttl() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn put(env: Env, admin: Address, key: Symbol) {
                    admin.require_auth();
                    env.storage().persistent().set_ttl(&key, 5_000_000u32);
                }
            }
            "#,
            Box::new(InconsistentTtlConstants),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("ttl=5000000"));
    }

    #[test]
    fn does_not_flag_values_inside_the_range() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn put(env: Env, admin: Address, key: Symbol, value: u32) {
                    admin.require_auth();
                    env.storage().persistent().set(&key, &value);
                    env.storage().persistent().extend_ttl(&key, 100, 518_400);
                    env.storage().persistent().set_ttl(&key, 1);
                }
            }
            "#,
            Box::new(InconsistentTtlConstants),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_non_literal_arguments() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn put(env: Env, admin: Address, key: Symbol, threshold: u32, bump: u32) {
                    admin.require_auth();
                    env.storage().persistent().extend_ttl(&key, threshold, bump);
                }
            }
            "#,
            Box::new(InconsistentTtlConstants),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }
}
