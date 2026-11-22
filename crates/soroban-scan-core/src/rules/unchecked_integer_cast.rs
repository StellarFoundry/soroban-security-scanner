//! SS-018: unchecked integer cast.

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{
    contract_entry_functions, integer_bit_width, location_for, CastFact, CastOrigin,
};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-018",
    title: "Unchecked integer cast",
    description: "A public contract entry point narrows an integer with `as`, \
where the operand comes from a function parameter or a storage read. In Rust an \
`as` cast between integers truncates the high bits and wraps instead of \
reporting an error, so an out-of-range amount, timestamp, or counter can become a \
small unintended value. Widenings and same-width casts are ignored. This is a \
syntactic heuristic and reports low confidence.",
    category: Category::Arithmetic,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Use fallible conversion: `u32::try_from(value)` / `value.try_into()` \
and handle the error with a typed contract error. Reserve `as` for casts whose \
range has already been checked.",
    references: &[
        "https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions",
        "https://doc.rust-lang.org/std/convert/trait.TryFrom.html",
    ],
};

/// Detects narrowing integer casts of parameters and storage values.
pub struct UncheckedIntegerCast;

impl Rule for UncheckedIntegerCast {
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
                for cast in ctx.cast_facts_for_function(source, &func).iter() {
                    if let Some(finding) = classify(cast, &func.name) {
                        let location = location_for(ctx, source, cast.line, cast.column);
                        out.push(Finding::new(&METADATA, location, finding));
                    }
                }
            }
        }
    }
}

/// Returns evidence text when the cast is a narrowing parameter/storage cast.
fn classify(cast: &CastFact, function: &str) -> Option<String> {
    let source_width = integer_bit_width(&cast.source_type)?;
    let target_width = integer_bit_width(&cast.target_type)?;
    if target_width >= source_width {
        return None;
    }
    let origin = match cast.origin {
        CastOrigin::Parameter => "parameter",
        CastOrigin::StorageRead => "storage value",
        CastOrigin::Local | CastOrigin::Other => return None,
    };
    Some(format!(
        "unchecked cast of {origin} from `{}` to `{}` in entry point `{function}`: {} \
         (use `TryFrom`/`try_into`)",
        cast.source_type, cast.target_type, cast.text
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_narrowing_parameter_cast() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(amount: i128) -> u32 {
                    amount as u32
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-018");
        assert!(findings[0].evidence.contains("parameter"));
        assert!(findings[0].evidence.contains("`i128` to `u32`"));
        assert!(findings[0].evidence.contains("TryFrom"));
    }

    #[test]
    fn flags_narrowing_storage_cast() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn get(env: Env) -> u32 {
                    let stored: u64 = env.storage().instance().get(&Key::Amount).unwrap();
                    stored as u32
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("storage value"));
        assert!(findings[0].evidence.contains("`u64` to `u32`"));
    }

    #[test]
    fn does_not_flag_widening_or_same_width_casts() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn widen(env: Env, small: u32) -> u128 {
                    let stored: u32 = env.storage().instance().get(&Key::Amount).unwrap();
                    let _ = small as u32;
                    let _ = stored as u64;
                    small as u128
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_try_into() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set(amount: i128) -> u32 {
                    u32::try_from(amount).unwrap_or(0)
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_other_integer_casts() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn literal() -> u8 {
                    1000u16 as u8
                }
                pub fn computed(amount: i128) -> u8 {
                    (amount + 1) as u8
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert!(findings.is_empty());
    }
}
