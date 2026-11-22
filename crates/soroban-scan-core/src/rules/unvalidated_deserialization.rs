//! SS-020: unvalidated XDR/bytes deserialization from caller input.

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::category::Category;
use crate::confidence::Confidence;
use crate::context::AnalysisContext;
use crate::finding::Finding;
use crate::rule::{Rule, RuleMetadata};
use crate::severity::Severity;

use super::util::{contract_entry_functions, location_for, ContractFn};

/// Rule metadata.
pub const METADATA: RuleMetadata = RuleMetadata {
    id: "SS-020",
    title: "Unvalidated XDR or bytes deserialization",
    description: "A contract entry point decodes caller-supplied bytes or XDR \
(`from_xdr`, `from_bytes`, or `try_from`) without checking the input length or \
handling a fallible decode result. Malformed or attacker-chosen payloads can \
yield unexpected values, panic the contract, or bypass validation that was \
assumed to happen during decoding. This is a syntactic heuristic and reports low \
confidence.",
    category: Category::ErrorHandling,
    default_severity: Severity::Medium,
    default_confidence: Confidence::Low,
    remediation: "Validate the payload length before decoding and handle the \
decode result explicitly with `match`, `?`, or a fallible helper that maps errors \
to a typed contract error. Reject trailing bytes and values outside the expected \
range.",
    references: &[
        "https://doc.rust-lang.org/std/convert/trait.TryFrom.html",
        "https://developers.stellar.org/docs/learn/encyclopedia/security",
    ],
};

/// Detects deserialization of caller-controlled bytes/XDR.
pub struct UnvalidatedDeserialization;

/// One deserialization call whose operands include caller-controlled bytes.
struct DeserCall {
    name: String,
    line: usize,
    column: usize,
    start: usize,
    params: BTreeSet<String>,
    text: String,
}

fn is_bytes_type(type_text: &str) -> bool {
    let lowered = type_text.to_ascii_lowercase();
    lowered.contains("bytes")
        || lowered.contains("u8")
        || lowered.contains("xdr")
        || lowered.contains("blob")
}

fn is_deserializer(name: &str) -> bool {
    matches!(name, "from_xdr" | "from_bytes" | "try_from")
}

fn is_result_handler(name: &str) -> bool {
    matches!(
        name,
        "unwrap"
            | "expect"
            | "unwrap_or"
            | "unwrap_or_else"
            | "unwrap_or_default"
            | "ok"
            | "ok_or"
            | "ok_or_else"
            | "map"
            | "map_err"
            | "to_result"
    )
}

/// Whole-identifier membership test over rendered source text.
fn mentions_ident(haystack: &str, needle: &str) -> bool {
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

fn referenced_tainted(expr: &syn::Expr, tainted: &BTreeSet<String>) -> BTreeSet<String> {
    let text = expr.to_token_stream().to_string();
    tainted
        .iter()
        .filter(|name| mentions_ident(&text, name))
        .cloned()
        .collect()
}

/// Parameters and simple local aliases that carry caller-supplied bytes.
fn tainted_names(func: &ContractFn<'_>) -> BTreeSet<String> {
    let mut tainted: BTreeSet<String> = func
        .param_types
        .iter()
        .filter(|(_, ty)| is_bytes_type(ty))
        .map(|(name, _)| name.clone())
        .collect();

    struct TaintVisitor<'a> {
        tainted: &'a BTreeSet<String>,
        discovered: BTreeSet<String>,
    }

    impl<'ast> Visit<'ast> for TaintVisitor<'_> {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
                // Only aliases of caller-derived values are tainted. A local
                // read from storage is never tainted, even when it is also
                // typed as bytes.
                if !referenced_tainted(&init.expr, self.tainted).is_empty() {
                    self.discovered.insert(pattern.ident.to_string());
                }
            }
            visit::visit_local(self, node);
        }
    }

    // Iterate until no new aliases appear so aliases of aliases are covered.
    loop {
        let mut visitor = TaintVisitor {
            tainted: &tainted,
            discovered: BTreeSet::new(),
        };
        visitor.visit_block(func.block);
        let before = tainted.len();
        tainted.extend(visitor.discovered);
        if tainted.len() == before {
            break;
        }
    }
    tainted
}

/// Byte-range span of a nested deserialization call, if the expression is one.
fn deser_span(expr: &syn::Expr) -> Option<(usize, usize)> {
    match expr {
        syn::Expr::Call(call) => {
            if let syn::Expr::Path(path) = &*call.func {
                let name = path
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default();
                if is_deserializer(&name) {
                    let span = call.span().byte_range();
                    return Some((span.start, span.end));
                }
            }
            None
        }
        syn::Expr::MethodCall(call) => {
            if is_deserializer(&call.method.to_string()) {
                let span = call.span().byte_range();
                return Some((span.start, span.end));
            }
            deser_span(&call.receiver)
        }
        syn::Expr::Paren(inner) => deser_span(&inner.expr),
        syn::Expr::Group(inner) => deser_span(&inner.expr),
        syn::Expr::Reference(inner) => deser_span(&inner.expr),
        syn::Expr::Unary(inner) => deser_span(&inner.expr),
        syn::Expr::Try(inner) => deser_span(&inner.expr),
        syn::Expr::Await(inner) => deser_span(&inner.base),
        _ => None,
    }
}

struct DeserVisitor<'a> {
    tainted: &'a BTreeSet<String>,
    calls: Vec<DeserCall>,
    handled: BTreeSet<(usize, usize)>,
}

impl<'ast, 'a> Visit<'ast> for DeserVisitor<'a> {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            let name = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            if is_deserializer(&name) {
                let mut params = BTreeSet::new();
                for arg in &node.args {
                    params.extend(referenced_tainted(arg, self.tainted));
                }
                if !params.is_empty() {
                    let start = node.span().start();
                    let span = node.span().byte_range();
                    self.calls.push(DeserCall {
                        name: name.clone(),
                        line: start.line,
                        column: start.column + 1,
                        start: span.start,
                        params,
                        text: truncate(&node.to_token_stream().to_string(), 160),
                    });
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        if is_deserializer(&name) {
            let mut params = referenced_tainted(&node.receiver, self.tainted);
            for arg in &node.args {
                params.extend(referenced_tainted(arg, self.tainted));
            }
            if !params.is_empty() {
                let start = node.span().start();
                let span = node.span().byte_range();
                self.calls.push(DeserCall {
                    name: name.clone(),
                    line: start.line,
                    column: start.column + 1,
                    start: span.start,
                    params,
                    text: truncate(&node.to_token_stream().to_string(), 160),
                });
            }
        }
        if is_result_handler(&name) {
            if let Some(span) = deser_span(&node.receiver) {
                self.handled.insert(span);
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_try(&mut self, node: &'ast syn::ExprTry) {
        if let Some(span) = deser_span(&node.expr) {
            self.handled.insert(span);
        }
        visit::visit_expr_try(self, node);
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if let Some(span) = deser_span(&node.expr) {
            self.handled.insert(span);
        }
        visit::visit_expr_match(self, node);
    }
}

/// Returns length checks that occur before `start`, keyed by tainted name.
fn length_checks_before(
    facts: &super::util::Facts,
    tainted: &BTreeSet<String>,
) -> BTreeMap<String, Vec<(usize, usize)>> {
    let mut checks: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    for comparison in &facts.comparisons {
        if !comparison.text.contains("len") {
            continue;
        }
        for name in tainted {
            if mentions_ident(&comparison.text, name) {
                checks
                    .entry(name.clone())
                    .or_default()
                    .push((comparison.line, comparison.column));
            }
        }
    }
    checks
}

impl Rule for UnvalidatedDeserialization {
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
                let tainted = tainted_names(&func);
                if tainted.is_empty() {
                    continue;
                }
                let facts = ctx.facts_for_function(source, &func);
                let checks = length_checks_before(&facts, &tainted);
                let mut visitor = DeserVisitor {
                    tainted: &tainted,
                    calls: Vec::new(),
                    handled: BTreeSet::new(),
                };
                visitor.visit_block(func.block);
                for call in visitor.calls {
                    if visitor
                        .handled
                        .iter()
                        .any(|(start, end)| *start <= call.start && call.start < *end)
                    {
                        continue;
                    }
                    let unchecked: Vec<String> = call
                        .params
                        .iter()
                        .filter(|name| {
                            checks.get(*name).is_none_or(|positions| {
                                positions
                                    .iter()
                                    .all(|position| *position > (call.line, call.column))
                            })
                        })
                        .cloned()
                        .collect();
                    if unchecked.is_empty() {
                        continue;
                    }
                    let params = unchecked.join("`, `");
                    let location = location_for(ctx, source, call.line, call.column);
                    let evidence = format!(
                        "`{}` decodes caller-controlled bytes `{params}` in entry point `{}` \
                         without a prior length check or handled decode result: {}",
                        call.name, func.name, call.text
                    );
                    out.push(Finding::new(&METADATA, location, evidence));
                }
            }
        }
    }
}

/// Truncates rendered source without splitting a UTF-8 code point.
fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::test_support::scan_rule;

    #[test]
    fn flags_from_xdr_of_parameter_bytes() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Bytes, Env};

            #[contractimpl]
            impl C {
                pub fn read(env: Env, payload: Bytes) -> u32 {
                    let value = u32::from_xdr(&env, &payload);
                    value
                }
            }
            "#,
            Box::new(UnvalidatedDeserialization),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SS-020");
        assert!(findings[0].evidence.contains("payload"));
        assert!(findings[0].evidence.contains("from_xdr"));
    }

    #[test]
    fn flags_try_from_of_local_alias() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Bytes, Env};

            #[contractimpl]
            impl C {
                pub fn read(env: Env, payload: Bytes) {
                    let raw = payload.clone();
                    let _ = Value::try_from(&env, &raw);
                }
            }
            "#,
            Box::new(UnvalidatedDeserialization),
        );
        assert_eq!(findings.len(), 1);
        assert!(findings[0].evidence.contains("raw"));
        assert!(findings[0].evidence.contains("try_from"));
    }

    #[test]
    fn does_not_flag_when_length_is_checked() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Bytes, Env};

            #[contractimpl]
            impl C {
                pub fn read(env: Env, payload: Bytes) -> u32 {
                    if payload.len() > 4 {
                        return 0;
                    }
                    u32::from_xdr(&env, &payload)
                }
            }
            "#,
            Box::new(UnvalidatedDeserialization),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_when_result_is_handled() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Bytes, Env};

            #[contractimpl]
            impl C {
                pub fn read(_env: Env, payload: Bytes) -> u32 {
                    Value::try_from(&payload).unwrap_or(0)
                }
            }
            "#,
            Box::new(UnvalidatedDeserialization),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_storage_bytes() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Bytes, Env};

            #[contractimpl]
            impl C {
                pub fn read(env: Env) -> u32 {
                    let payload: Bytes = env.storage().instance().get(&Key::Data).unwrap();
                    u32::from_xdr(&env, &payload)
                }
            }
            "#,
            Box::new(UnvalidatedDeserialization),
        );
        assert!(findings.is_empty(), "got: {findings:#?}");
    }

    #[test]
    fn does_not_flag_private_helpers() {
        let findings = scan_rule(
            r#"
            use soroban_sdk::{contractimpl, Bytes, Env};

            #[contractimpl]
            impl C {
                fn read(env: Env, payload: Bytes) -> u32 {
                    u32::from_xdr(&env, &payload)
                }
            }
            "#,
            Box::new(UnvalidatedDeserialization),
        );
        assert!(findings.is_empty());
    }
}
