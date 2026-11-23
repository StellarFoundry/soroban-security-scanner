//! SS-048: unbounded event payload.
//!
//! Publishing a `Vec`, `Map`, `Bytes`, or `String` from an entry point lets a
//! caller choose how much data the event carries. Event payloads are written to
//! the ledger, so an unbounded payload raises fees and can exceed transaction or
//! ledger limits. The detector reports only when the unbounded type is visible
//! in the source: a parameter type used in an `events().publish(...)` payload,
//! or a field of a `#[contractevent]` struct.

use std::collections::BTreeSet;

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, Facts};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-048",
    title: "Unbounded event payload",
    description: "Publishing an unbounded `Vec`, `Map`, `Bytes`, or `String` in \
an event lets a caller choose the payload size. Events are written to the ledger, \
so an oversized payload raises fees and can exceed transaction or ledger limits, \
making the emission fail or the transaction unaffordable.",
    category: Category::Events,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Medium,
    remediation: "Bound the payload before publishing: reject values above a \
documented maximum with `if value.len() > MAX { return Err(...) }`, publish only \
a fixed-size summary such as a count or a hash, and keep unbounded collections \
and strings in storage rather than in events.",
    references: &[
        "https://developers.stellar.org/docs/learn/encyclopedia/events",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects event publications whose payload type is unbounded.
pub struct UnboundedEventPayload;

impl Rule for UnboundedEventPayload {
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

            // `#[contractevent]` declarations describe the payload type directly.
            let mut declarations = Vec::new();
            collect_event_structs(&file.items, &mut declarations);
            for declaration in declarations {
                let mut fields = BTreeSet::new();
                for field in &declaration.fields {
                    let Some(ident) = &field.ident else {
                        continue;
                    };
                    if let Some(kind) = unbounded_type(&render_type(&field.ty)) {
                        fields.insert(format!("`{ident}` ({kind})"));
                    }
                }
                if fields.is_empty() {
                    continue;
                }
                let start = declaration.ident.span().start();
                let location = location_for(ctx, source, start.line, start.column + 1);
                let evidence = format!(
                    "`#[contractevent]` struct `{}` declares unbounded payload \
                     field(s): {}",
                    declaration.ident,
                    fields.into_iter().collect::<Vec<_>>().join(", ")
                );
                out.push(Finding::new(&METADATA, location, evidence));
            }

            for func in contract_entry_functions(file) {
                if !func.is_public {
                    continue;
                }
                let unbounded_params: Vec<(String, &'static str)> = func
                    .param_types
                    .iter()
                    .filter_map(|(name, ty)| unbounded_type(ty).map(|kind| (name.clone(), kind)))
                    .collect();
                if unbounded_params.is_empty() {
                    continue;
                }

                let facts = ctx.facts_for_function(source, &func);
                for call in &facts.method_calls {
                    if call.name != "publish"
                        || !call.context.to_ascii_lowercase().contains("event")
                    {
                        continue;
                    }
                    let Some(payload) = call.args.get(1) else {
                        continue;
                    };
                    let mut reported = BTreeSet::new();
                    for (param, kind) in &unbounded_params {
                        if !reported.insert(param.as_str()) {
                            continue;
                        }
                        if !contains_ident(payload, param) {
                            continue;
                        }
                        if has_length_bound(&facts, param, call.line, call.column) {
                            continue;
                        }
                        let location = location_for(ctx, source, call.line, call.column);
                        let evidence = format!(
                            "event publish in `{}` includes user-controlled `{kind}` \
                             parameter `{param}` with no visible length bound: {}",
                            func.name, call.text
                        );
                        out.push(Finding::new(&METADATA, location, evidence));
                    }
                }
            }
        }
    }
}

/// Collects `#[contractevent]` struct declarations, recursing into modules.
fn collect_event_structs<'a>(items: &'a [syn::Item], out: &mut Vec<&'a syn::ItemStruct>) {
    for item in items {
        match item {
            syn::Item::Struct(item_struct) if is_contract_event(&item_struct.attrs) => {
                out.push(item_struct);
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_event_structs(nested, out);
                }
            }
            _ => {}
        }
    }
}

fn is_contract_event(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "contractevent")
    })
}

fn render_type(ty: &syn::Type) -> String {
    use quote::ToTokens;
    ty.to_token_stream().to_string()
}

/// Whether the rendered type is one of the unbounded collection/string types.
///
/// `BytesN` is fixed-size and is deliberately not reported.
fn unbounded_type(type_text: &str) -> Option<&'static str> {
    let trimmed = type_text.trim().trim_start_matches('&').trim();
    let last = trimmed.rsplit("::").next().unwrap_or(trimmed).trim();
    let base = last.split('<').next().unwrap_or(last).trim();
    match base {
        "Vec" => Some("Vec"),
        "Map" => Some("Map"),
        "Bytes" => Some("Bytes"),
        "String" => Some("String"),
        _ => None,
    }
}

/// Whether a `.len()` comparison constrains `param` before the publish.
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
    fn flags_unbounded_vec_published() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn record(env: Env, items: Vec<Address>) {
                    env.events().publish(symbol_short!("record"), items);
                }
            }
            "#,
            Box::new(UnboundedEventPayload),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-048");
        assert!(findings[0].evidence.contains("`Vec` parameter `items`"));
    }

    #[test]
    fn flags_unbounded_string_in_tuple_payload() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn note(env: Env, memo: String) {
                    env.events().publish((symbol_short!("note"),), (1, memo));
                }
            }
            "#,
            Box::new(UnboundedEventPayload),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("`String` parameter `memo`"));
    }

    #[test]
    fn flags_unbounded_contract_event_field() {
        let findings = scan_rule(
            r#"
            #[contractevent]
            pub struct Recorded {
                pub items: Vec<Address>,
                pub count: u32,
            }

            #[contractimpl]
            impl C {
                pub fn record(env: Env, items: Vec<Address>) {
                    env.events().publish(symbol_short!("record"), 1u32);
                    let _ = items;
                }
            }
            "#,
            Box::new(UnboundedEventPayload),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .evidence
            .contains("`#[contractevent]` struct `Recorded`"));
        assert!(findings[0].evidence.contains("`items` (Vec)"));
    }

    #[test]
    fn does_not_flag_when_payload_is_length_bounded() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                pub fn record(env: Env, items: Vec<Address>) {
                    if items.len() > 32 {
                        panic!("too many items");
                    }
                    env.events().publish(symbol_short!("record"), items);
                }
            }
            "#,
            Box::new(UnboundedEventPayload),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_fixed_size_payloads() {
        let findings = scan_rule(
            r#"
            #[contractevent]
            pub struct Recorded {
                pub digest: BytesN<32>,
                pub count: u32,
            }

            #[contractimpl]
            impl C {
                pub fn record(env: Env, digest: BytesN<32>, count: u32) {
                    env.events().publish(symbol_short!("record"), (digest, count));
                }
            }
            "#,
            Box::new(UnboundedEventPayload),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            #[contractimpl]
            impl C {
                fn emit(env: Env, items: Vec<Address>) {
                    env.events().publish(symbol_short!("record"), items);
                }
            }
            "#,
            Box::new(UnboundedEventPayload),
        );
        assert!(findings.is_empty());
    }
}
