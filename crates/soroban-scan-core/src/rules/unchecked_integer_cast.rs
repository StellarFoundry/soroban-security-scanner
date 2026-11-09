//! SS-018: unchecked integer cast in a contract entry point.

use std::collections::{BTreeMap, BTreeSet};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, facts_from_block_with_imports, location_for};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-018",
    title: "Unchecked integer cast in a contract entry point",
    description: "A public contract entry point uses an `as` cast to narrow or \
change the signedness of an integer value derived from a function parameter or \
contract storage. In Rust, `as` casts between integer types never panic: \
narrowing casts silently truncate high-order bits and signed/unsigned casts \
reinterpret two's-complement bit patterns, which can turn negative or oversized \
inputs into corrupted balances, amounts, or counters. This is a heuristic with \
low confidence because prior bounds checks may make the cast safe in context.",
    category: Category::Arithmetic,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Replace narrowing or sign-changing `as` casts with fallible \
conversions using `core::convert::TryFrom` / `TryInto` (`u64::try_from(value)` \
or `value.try_into()`) and handle the `Err` branch with a typed contract error.",
    references: &[
        "https://doc.rust-lang.org/reference/expressions/operator-expr.html#type-cast-expressions",
        "https://doc.rust-lang.org/core/convert/trait.TryFrom.html",
    ],
};

/// Detects unchecked narrowing or sign-changing integer `as` casts on parameters or storage reads.
pub struct UncheckedIntegerCast;

/// Parsed integer type width and signedness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IntSpec {
    bits: u16,
    signed: bool,
}

/// Parses a Rust primitive integer type name into its width (using 32 bits for
/// `usize`/`isize` on `wasm32` Soroban targets) and signedness.
fn parse_int_type(ty: &str) -> Option<IntSpec> {
    match ty.trim() {
        "u8" => Some(IntSpec {
            bits: 8,
            signed: false,
        }),
        "u16" => Some(IntSpec {
            bits: 16,
            signed: false,
        }),
        "u32" | "usize" => Some(IntSpec {
            bits: 32,
            signed: false,
        }),
        "u64" => Some(IntSpec {
            bits: 64,
            signed: false,
        }),
        "u128" => Some(IntSpec {
            bits: 128,
            signed: false,
        }),
        "i8" => Some(IntSpec {
            bits: 8,
            signed: true,
        }),
        "i16" => Some(IntSpec {
            bits: 16,
            signed: true,
        }),
        "i32" | "isize" => Some(IntSpec {
            bits: 32,
            signed: true,
        }),
        "i64" => Some(IntSpec {
            bits: 64,
            signed: true,
        }),
        "i128" => Some(IntSpec {
            bits: 128,
            signed: true,
        }),
        _ => None,
    }
}

/// Returns `true` when every value of `src` is losslessly representable in `dst`.
///
/// - Same signedness (`uN -> uM` or `iN -> iM`): safe when `dst.bits >= src.bits`.
/// - Unsigned to signed (`uN -> iM`): safe when `dst.bits > src.bits`.
/// - Signed to unsigned (`iN -> uM`): never unconditionally safe (negative values wrap).
fn is_widening_or_same_width(src: IntSpec, dst: IntSpec) -> bool {
    match (src.signed, dst.signed) {
        (false, false) | (true, true) => dst.bits >= src.bits,
        (false, true) => dst.bits > src.bits,
        (true, false) => false,
    }
}

/// Extracts simple identifier tokens from a rendered expression string.
fn identifiers_in_expr(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in expr.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else if !current.is_empty() {
            if !current.chars().next().unwrap().is_ascii_digit() {
                out.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
        }
    }
    if !current.is_empty() && !current.chars().next().unwrap().is_ascii_digit() {
        out.push(current);
    }
    out
}

/// Checks whether the rendered operand expression is a direct storage read
/// (`env.storage()...get(...)`) or references a parameter or storage variable.
fn operand_source_and_type(
    expr: &str,
    explicit_source_type: Option<&str>,
    integer_params: &BTreeSet<String>,
    storage_vars: &BTreeSet<String>,
    type_env: &BTreeMap<String, String>,
) -> Option<(&'static str, Option<String>)> {
    let lowered = expr.to_ascii_lowercase();
    if lowered.contains("storage") && lowered.contains("get") {
        return Some(("storage read", explicit_source_type.map(str::to_string)));
    }

    let idents = identifiers_in_expr(expr);
    for ident in &idents {
        if storage_vars.contains(ident) {
            let inferred = explicit_source_type
                .map(str::to_string)
                .or_else(|| type_env.get(ident).cloned());
            return Some(("storage value", inferred));
        }
    }
    for ident in &idents {
        if integer_params.contains(ident) {
            let inferred = explicit_source_type
                .map(str::to_string)
                .or_else(|| type_env.get(ident).cloned());
            return Some(("parameter", inferred));
        }
    }

    None
}

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
                let facts = facts_from_block_with_imports(func.block, &source.imports);
                let mut type_env = func.param_types.clone();
                for (k, v) in &facts.local_types {
                    type_env.insert(k.clone(), v.clone());
                }

                let integer_params: BTreeSet<String> = func
                    .param_types
                    .iter()
                    .filter(|(_, ty)| parse_int_type(ty).is_some())
                    .map(|(name, _)| name.clone())
                    .collect();

                for cast in facts.cast_ops() {
                    let Some(target_int) = parse_int_type(&cast.target_type) else {
                        continue;
                    };

                    let Some((origin, inferred_src_ty)) = operand_source_and_type(
                        &cast.expr,
                        cast.source_type.as_deref(),
                        &integer_params,
                        &facts.storage_vars,
                        &type_env,
                    ) else {
                        continue;
                    };

                    if let Some(src_ty_name) = &inferred_src_ty {
                        let Some(source_int) = parse_int_type(src_ty_name) else {
                            continue;
                        };
                        if is_widening_or_same_width(source_int, target_int) {
                            continue;
                        }
                        let location = location_for(ctx, source, cast.line, cast.column);
                        let evidence = format!(
                            "unchecked integer cast from `{}` ({}) to `{}` in entry point `{}`: {} (use `try_into()` or `{}::try_from`)",
                            src_ty_name,
                            origin,
                            cast.target_type,
                            func.name,
                            cast.text,
                            cast.target_type
                        );
                        out.push(Finding::new(&METADATA, location, evidence));
                    } else if target_int.bits < 128 {
                        let location = location_for(ctx, source, cast.line, cast.column);
                        let evidence = format!(
                            "unchecked integer cast of {} to `{}` in entry point `{}`: {} (use `try_into()` or `{}::try_from`)",
                            origin,
                            cast.target_type,
                            func.name,
                            cast.text,
                            cast.target_type
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
    fn flags_narrowing_cast_of_parameter() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Env};

            #[contractimpl]
            impl Vault {
                pub fn deposit(env: Env, amount: i128) -> u64 {
                    amount as u64
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-018");
        assert!(findings[0]
            .evidence
            .contains("unchecked integer cast from `i128` (parameter) to `u64`"));
    }

    #[test]
    fn flags_sign_changing_cast_of_same_width() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Env};

            #[contractimpl]
            impl Vault {
                pub fn normalize(env: Env, delta: i64) -> u64 {
                    delta as u64
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-018");
    }

    #[test]
    fn flags_narrowing_cast_from_storage_read() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, symbol_short, Env};

            #[contractimpl]
            impl Vault {
                pub fn snapshot(env: Env) -> u32 {
                    let total: i128 = env
                        .storage()
                        .persistent()
                        .get(&symbol_short!("TOTAL"))
                        .unwrap_or(0);
                    total as u32
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-018");
        assert!(findings[0].evidence.contains("storage value"));
    }

    #[test]
    fn ignores_widening_and_same_width_casts() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Env};

            #[contractimpl]
            impl Vault {
                pub fn scale(env: Env, raw: u32, fee_bps: u16, delta: i64) -> i128 {
                    let widened_u64 = raw as u64;
                    let same_u64 = widened_u64 as u64;
                    let widened_signed = fee_bps as i64;
                    (same_u64 as i128) + (widened_signed as i128) + (delta as i128)
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }

    #[test]
    fn ignores_try_into_and_local_constants() {
        let findings = scan_rule(
            r#"
            use core::convert::TryInto;
            use soroban_sdk::{contractimpl, Env};

            #[contractimpl]
            impl Vault {
                pub fn deposit(env: Env, amount: i128) -> u64 {
                    let fixed_fee: u64 = 100;
                    let _small_fee = fixed_fee as u32;
                    amount.try_into().unwrap_or(0)
                }
            }
            "#,
            Box::new(UncheckedIntegerCast),
        );
        assert!(findings.is_empty(), "unexpected findings: {findings:#?}");
    }
}
