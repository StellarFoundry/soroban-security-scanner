//! SS-025: unbounded string/bytes persistence.
//!
//! Persisting caller-controlled `String`/`Bytes` values without a length bound
//! grows ledger entries, increasing rent and potentially exceeding limits. The
//! detector flags storage writes of string/bytes parameters unless a visible
//! `.len()` comparison guards the write.

use std::collections::BTreeSet;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, CallFact, Facts};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-025",
    title: "Unbounded string/bytes persisted from caller input",
    description: "Persisting a caller-controlled `String` or `Bytes` value \
without a length check lets an attacker grow ledger entries without bound, \
raising rent and potentially exceeding limits. The detector looks for a visible \
`.len()` comparison guarding the write.",
    category: Category::Storage,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Reject or truncate values above an explicit maximum before \
persisting them (for example `if value.len() > MAX { return Err(...) }`). Storing \
a fixed-size hash instead of the raw value is usually safer.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/storage/persisting-data",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects unbounded string/bytes values written to storage.
pub struct UnboundedBytesPersistence;

impl Rule for UnboundedBytesPersistence {
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
                let string_params: Vec<(String, &'static str)> = func
                    .param_types
                    .iter()
                    .filter_map(|(name, ty)| {
                        string_or_bytes_type(ty).map(|kind| (name.clone(), kind))
                    })
                    .collect();
                if string_params.is_empty() {
                    continue;
                }

                let facts = ctx.facts_for_function(source, &func);

                // `env.storage()...set(key, value)`.
                for call in &facts.method_calls {
                    if !is_storage_write(call) {
                        continue;
                    }
                    if let Some(value) = call.args.get(1) {
                        report_unbounded(
                            ctx,
                            source,
                            out,
                            &func.name,
                            call,
                            value,
                            &string_params,
                            &facts,
                        );
                    }
                }

                // UFCS form: `Storage::set(&store, key, value)`.
                for call in &facts.function_calls {
                    if !is_storage_write(call) {
                        continue;
                    }
                    if let Some(value) = call.args.last() {
                        report_unbounded(
                            ctx,
                            source,
                            out,
                            &func.name,
                            call,
                            value,
                            &string_params,
                            &facts,
                        );
                    }
                }
            }
        }
    }
}

fn is_storage_write(call: &CallFact) -> bool {
    matches!(call.name.as_str(), "set" | "update")
        && call.context.to_ascii_lowercase().contains("storage")
}

#[allow(clippy::too_many_arguments)]
fn report_unbounded(
    ctx: &AnalysisContext<'_>,
    source: &crate::source::ParsedSource,
    out: &mut Vec<Finding>,
    function: &str,
    call: &CallFact,
    value: &str,
    string_params: &[(String, &'static str)],
    facts: &Facts,
) {
    let mut reported: BTreeSet<&str> = BTreeSet::new();
    for (param, kind) in string_params {
        if !contains_ident(value, param) || reported.contains(param.as_str()) {
            continue;
        }
        if has_length_bound(facts, param, call.line, call.column) {
            continue;
        }
        reported.insert(param);
        let location = location_for(ctx, source, call.line, call.column);
        let evidence = format!(
            "user-controlled `{kind}` parameter `{param}` persisted without a length \
             bound in `{function}`: {}",
            call.text
        );
        out.push(Finding::new(&METADATA, location, evidence));
    }
}

/// Whether the rendered value type is Soroban `String` or `Bytes`.
fn string_or_bytes_type(type_text: &str) -> Option<&'static str> {
    let trimmed = type_text.trim().trim_start_matches('&').trim();
    let last = trimmed.rsplit("::").next().unwrap_or(trimmed).trim();
    match last {
        "String" => Some("String"),
        "Bytes" => Some("Bytes"),
        _ => None,
    }
}

/// Whether a `.len()` comparison constrains `param` before the write.
fn has_length_bound(facts: &Facts, param: &str, line: usize, column: usize) -> bool {
    facts.comparisons.iter().any(|comparison| {
        matches!(comparison.op.as_str(), "<" | "<=" | ">" | ">=")
            && (comparison.line, comparison.column) <= (line, column)
            && contains_ident(&comparison.text, "len")
            && contains_ident(&comparison.text, param)
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_unbounded_string_persisted() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_name(env: Env, name: String) {
                    env.storage().persistent().set(&DataKey::Name, &name);
                }
            }
            "#,
            Box::new(UnboundedBytesPersistence),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-025");
        assert!(findings[0].evidence.contains("parameter `name`"));
    }

    #[test]
    fn flags_unbounded_bytes_persisted() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_blob(env: Env, blob: Bytes) {
                    env.storage().persistent().set(&DataKey::Blob, &blob);
                }
            }
            "#,
            Box::new(UnboundedBytesPersistence),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("`Bytes`"));
    }

    #[test]
    fn does_not_flag_when_length_is_bounded() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_name(env: Env, name: String) {
                    if name.len() > 64 {
                        panic!("too long");
                    }
                    env.storage().persistent().set(&DataKey::Name, &name);
                }
            }
            "#,
            Box::new(UnboundedBytesPersistence),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_bounded_numeric_values() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_amount(env: Env, amount: u32) {
                    env.storage().persistent().set(&DataKey::Amount, &amount);
                }
            }
            "#,
            Box::new(UnboundedBytesPersistence),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn set_name(env: Env, name: String) {
                    env.storage().persistent().set(&DataKey::Name, &name);
                }
            }
            "#,
            Box::new(UnboundedBytesPersistence),
        );
        assert!(findings.is_empty());
    }
}
