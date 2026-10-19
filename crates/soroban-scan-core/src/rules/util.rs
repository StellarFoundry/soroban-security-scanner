//! Shared AST analysis utilities for rules.
//!
//! These helpers extract *facts* from a parsed function. Rules combine facts to
//! decide whether concrete evidence justifies a finding. No helper here makes a
//! security judgment on its own.

use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::context::AnalysisContext;
use crate::finding::SourceLocation;
use crate::soroban::{self, ContractAttrStrength};
use crate::source::{attribute_path, ParsedSource};

/// Method names that mutate Soroban storage.
pub const STORAGE_MUTATORS: &[&str] = &["set", "remove", "update", "extend_ttl", "set_ttl", "bump"];

/// Method names that iterate storage.
pub const STORAGE_ITERATORS: &[&str] = &["iter", "keys", "values"];

/// Method names that manage TTL.
pub const TTL_MANAGERS: &[&str] = &["extend_ttl", "set_ttl", "bump"];

/// Panic-prone method calls.
pub const PANIC_METHODS: &[&str] = &["unwrap", "expect"];

/// Panic-prone macros.
pub const PANIC_MACROS: &[&str] = &["panic", "todo", "unimplemented", "unreachable"];

/// A call-like fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallFact {
    /// Method or function name.
    pub name: String,
    /// Rendered receiver or path, used for context checks.
    pub context: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// Start byte offset in the parsed source, used to order facts.
    pub start_byte: usize,
    /// End byte offset in the parsed source.
    pub end_byte: usize,
    /// Rendered call text (may be truncated by consumers).
    pub text: String,
}

/// A macro invocation fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroFact {
    /// Macro name (last path segment).
    pub name: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// Rendered invocation text.
    pub text: String,
}

/// A string literal fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringFact {
    /// Literal value.
    pub value: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
}

/// A binary arithmetic fact (`+`, `-`, or `*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArithFact {
    /// Operator text (`+`, `-`, `*`, or `%`).
    pub op: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// Rendered expression text (may be truncated).
    pub text: String,
}

/// A binary comparison fact (`==`, `!=`, `<`, `<=`, `>`, or `>=`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonFact {
    /// Operator text.
    pub op: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// Rendered expression text (may be truncated).
    pub text: String,
}

/// Facts extracted from a function body or file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Method calls.
    pub method_calls: Vec<CallFact>,
    /// Free/associated function calls.
    pub function_calls: Vec<CallFact>,
    /// Macro invocations.
    pub macros: Vec<MacroFact>,
    /// String literals.
    pub strings: Vec<StringFact>,
    /// Binary arithmetic operations (`+`, `-`, `*`).
    pub arith: Vec<ArithFact>,
    /// Binary remainder operations (`%`).
    pub modulo: Vec<ArithFact>,
    /// Binary comparison operations.
    pub comparisons: Vec<ComparisonFact>,
    /// Method calls on a local cross-contract client variable.
    pub client_calls: Vec<CallFact>,
    /// Whether the code contains `unsafe`.
    pub has_unsafe: bool,
    /// Locations of `unsafe` constructs.
    pub unsafe_locations: Vec<(usize, usize)>,
}

impl Facts {
    /// Returns true if a `require_auth`-style call is present.
    pub fn has_require_auth(&self) -> bool {
        self.method_calls
            .iter()
            .any(|c| c.name == "require_auth" || c.name == "require_auth_for_args")
    }

    /// Storage mutation calls.
    pub fn storage_mutations(&self) -> Vec<&CallFact> {
        self.method_calls
            .iter()
            .filter(|c| {
                STORAGE_MUTATORS.contains(&c.name.as_str())
                    && c.context.to_ascii_lowercase().contains("storage")
            })
            .collect()
    }

    /// Persistent-storage mutation calls.
    pub fn persistent_mutations(&self) -> Vec<&CallFact> {
        self.storage_mutations()
            .into_iter()
            .filter(|c| c.context.to_ascii_lowercase().contains("persistent"))
            .collect()
    }

    /// Storage iteration calls.
    pub fn storage_iterations(&self) -> Vec<&CallFact> {
        self.method_calls
            .iter()
            .filter(|c| {
                STORAGE_ITERATORS.contains(&c.name.as_str())
                    && c.context.to_ascii_lowercase().contains("storage")
            })
            .collect()
    }

    /// TTL management calls.
    pub fn ttl_management(&self) -> Vec<&CallFact> {
        self.method_calls
            .iter()
            .filter(|c| TTL_MANAGERS.contains(&c.name.as_str()))
            .collect()
    }

    /// Cross-contract client constructors (`SomeClient::new(...)`).
    pub fn cross_contract_constructors(&self) -> Vec<&CallFact> {
        self.function_calls
            .iter()
            .filter(|c| c.name == "new" && c.context.contains("Client"))
            .collect()
    }

    /// Cross-contract call sites in source order.
    ///
    /// Calls through a local client variable are preferred; when none can be
    /// resolved, constructors are used as a conservative fallback.
    pub fn ordered_cross_contract_calls(&self) -> Vec<&CallFact> {
        let mut calls: Vec<&CallFact> = if self.client_calls.is_empty() {
            self.cross_contract_constructors()
        } else {
            self.client_calls.iter().collect()
        };
        calls.sort_by_key(|c| (c.start_byte, c.line, c.column));
        calls
    }

    /// Ledger accessor calls (`ledger().timestamp()` / `ledger().sequence()`).
    pub fn ledger_accesses(&self) -> Vec<&CallFact> {
        self.method_calls
            .iter()
            .filter(|c| {
                (c.name == "timestamp" || c.name == "sequence")
                    && c.context.to_ascii_lowercase().contains("ledger")
            })
            .collect()
    }

    /// Panic-prone calls and macros.
    pub fn panics(&self) -> Vec<(&str, usize, usize, &str)> {
        let mut found: Vec<(&str, usize, usize, &str)> = Vec::new();
        for c in &self.method_calls {
            if PANIC_METHODS.contains(&c.name.as_str()) {
                found.push((c.name.as_str(), c.line, c.column, c.text.as_str()));
            }
        }
        for m in &self.macros {
            if PANIC_MACROS.contains(&m.name.as_str()) {
                found.push((m.name.as_str(), m.line, m.column, m.text.as_str()));
            }
        }
        found.sort_by_key(|(_, line, col, _)| (*line, *col));
        found
    }

    /// Binary arithmetic operations (`+`, `-`, `*`) in source order.
    pub fn arithmetic_ops(&self) -> &[ArithFact] {
        &self.arith
    }
}

#[derive(Default)]
struct FactsVisitor {
    facts: Facts,
    unsafe_depth: usize,
    client_vars: BTreeSet<String>,
}

fn span_line_col<T: Spanned>(node: &T) -> (usize, usize) {
    let start = node.span().start();
    (start.line, start.column + 1)
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        text.to_string()
    } else {
        format!("{}...", &text[..max])
    }
}

impl<'ast> Visit<'ast> for FactsVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let (line, column) = span_line_col(node);
        let span = node.span().byte_range();
        let receiver_ident = match &*node.receiver {
            syn::Expr::Path(path) if path.path.segments.len() == 1 => {
                Some(path.path.segments[0].ident.to_string())
            }
            _ => None,
        };
        let is_client_call = receiver_ident
            .as_ref()
            .is_some_and(|name| self.client_vars.contains(name));
        let fact = CallFact {
            name: node.method.to_string(),
            context: node.receiver.to_token_stream().to_string(),
            line,
            column,
            start_byte: span.start,
            end_byte: span.end,
            text: truncate(&node.to_token_stream().to_string(), 160),
        };
        if is_client_call {
            self.facts.client_calls.push(fact.clone());
        }
        self.facts.method_calls.push(fact);
        visit::visit_expr_method_call(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
            if let syn::Expr::Call(call) = &*init.expr {
                if let syn::Expr::Path(path) = &*call.func {
                    let name = path
                        .path
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                        .unwrap_or_default();
                    let context = path.path.to_token_stream().to_string();
                    if name == "new" && context.contains("Client") {
                        self.client_vars.insert(pattern.ident.to_string());
                    }
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*node.func {
            let (line, column) = span_line_col(node);
            let name = path
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            let span = node.span().byte_range();
            self.facts.function_calls.push(CallFact {
                name,
                context: path.path.to_token_stream().to_string(),
                line,
                column,
                start_byte: span.start,
                end_byte: span.end,
                text: truncate(&node.to_token_stream().to_string(), 160),
            });
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let (line, column) = span_line_col(node);
        let name = node
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        self.facts.macros.push(MacroFact {
            name,
            line,
            column,
            text: truncate(&node.to_token_stream().to_string(), 160),
        });
        visit::visit_macro(self, node);
    }

    fn visit_lit(&mut self, node: &'ast syn::Lit) {
        if let syn::Lit::Str(s) = node {
            let (line, column) = span_line_col(node);
            self.facts.strings.push(StringFact {
                value: s.value(),
                line,
                column,
            });
        }
        visit::visit_lit(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let (line, column) = span_line_col(node);
        let text = truncate(&node.to_token_stream().to_string(), 160);
        let arithmetic_op = match node.op {
            syn::BinOp::Add(_) => Some("+"),
            syn::BinOp::Sub(_) => Some("-"),
            syn::BinOp::Mul(_) => Some("*"),
            _ => None,
        };
        if let Some(op) = arithmetic_op {
            self.facts.arith.push(ArithFact {
                op: op.to_string(),
                line,
                column,
                text: text.clone(),
            });
        }
        if matches!(node.op, syn::BinOp::Rem(_)) {
            self.facts.modulo.push(ArithFact {
                op: "%".to_string(),
                line,
                column,
                text: text.clone(),
            });
        }
        let comparison_op = match node.op {
            syn::BinOp::Eq(_) => Some("=="),
            syn::BinOp::Ne(_) => Some("!="),
            syn::BinOp::Lt(_) => Some("<"),
            syn::BinOp::Le(_) => Some("<="),
            syn::BinOp::Gt(_) => Some(">"),
            syn::BinOp::Ge(_) => Some(">="),
            _ => None,
        };
        if let Some(op) = comparison_op {
            self.facts.comparisons.push(ComparisonFact {
                op: op.to_string(),
                line,
                column,
                text,
            });
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.unsafe_depth += 1;
        let (line, column) = span_line_col(node);
        self.facts.has_unsafe = true;
        self.facts.unsafe_locations.push((line, column));
        visit::visit_expr_unsafe(self, node);
        self.unsafe_depth -= 1;
    }
}

/// Extracts facts from a block.
pub fn facts_from_block(block: &syn::Block) -> Facts {
    let mut visitor = FactsVisitor::default();
    visitor.visit_block(block);
    visitor.facts
}

/// Extracts facts from a whole file.
pub fn facts_from_file(file: &syn::File) -> Facts {
    let mut visitor = FactsVisitor::default();
    visitor.visit_file(file);
    visitor.facts
}

/// Maximum depth of the intra-file helper walk.
///
/// Bounds interprocedural expansion so adversarial or deeply nested call chains
/// cannot cause unbounded work. The walk is deterministic: the same input always
/// expands the same set of helpers, in the same order.
pub const HELPER_SUMMARY_MAX_DEPTH: usize = 3;

/// Collects facts for every function defined in the file, keyed by name.
///
/// Includes free functions and inherent/impl methods (public or private),
/// recursing into inline modules. When a name is defined more than once, the
/// first definition in source order wins, so resolution stays deterministic.
pub fn function_facts(file: &syn::File) -> BTreeMap<String, Facts> {
    let mut map = BTreeMap::new();
    collect_function_facts(&file.items, &mut map);
    map
}

fn collect_function_facts(items: &[syn::Item], out: &mut BTreeMap<String, Facts>) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                out.entry(f.sig.ident.to_string())
                    .or_insert_with(|| facts_from_block(&f.block));
            }
            syn::Item::Impl(imp) => {
                for impl_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = impl_item {
                        out.entry(f.sig.ident.to_string())
                            .or_insert_with(|| facts_from_block(&f.block));
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, sub)) = &m.content {
                    collect_function_facts(sub, out);
                }
            }
            _ => {}
        }
    }
}

/// Returns the entry point's facts merged with transitively reachable intra-file
/// helpers, up to [`HELPER_SUMMARY_MAX_DEPTH`].
///
/// Convenience wrapper around [`facts_with_helpers_from`] that computes the
/// file summaries first. Prefer [`facts_with_helpers_from`] when analyzing many
/// entry points in the same file (computing summaries once avoids quadratic
/// work on files with many functions).
pub fn facts_with_helpers(file: &syn::File, entry: &ContractFn<'_>) -> Facts {
    let summaries = function_facts(file);
    facts_with_helpers_from(&summaries, entry)
}

/// Like [`facts_with_helpers`] but reuses a precomputed summary map.
///
/// Only calls that resolve to a function defined in the **same file** are
/// followed, so unrelated calls are ignored. The merge is deterministic (helpers
/// are visited in sorted name order) and cycle-safe (each function is visited
/// once). This narrows false positives for rules such as SS-001 (authorization
/// performed in a helper) and SS-006 (TTL managed in a helper) without claiming
/// whole-program analysis.
pub fn facts_with_helpers_from(
    summaries: &BTreeMap<String, Facts>,
    entry: &ContractFn<'_>,
) -> Facts {
    let mut merged = facts_from_block(entry.block);
    let mut visited: BTreeSet<String> = BTreeSet::new();
    visited.insert(entry.name.clone());

    let mut frontier = direct_callees(&merged, summaries);
    let mut depth = 0;
    while !frontier.is_empty() && depth < HELPER_SUMMARY_MAX_DEPTH {
        let mut next: Vec<String> = Vec::new();
        for name in frontier {
            if !visited.insert(name.clone()) {
                continue;
            }
            let Some(facts) = summaries.get(&name) else {
                continue;
            };
            merge_facts(&mut merged, facts);
            for callee in direct_callees(facts, summaries) {
                if !visited.contains(&callee) {
                    next.push(callee);
                }
            }
        }
        next.sort();
        next.dedup();
        frontier = next;
        depth += 1;
    }
    merged
}

/// Names of functions defined in `summaries` that this fact set calls.
fn direct_callees(facts: &Facts, summaries: &BTreeMap<String, Facts>) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for call in facts.function_calls.iter().chain(facts.method_calls.iter()) {
        if summaries.contains_key(&call.name) {
            names.insert(call.name.clone());
        }
    }
    names.into_iter().collect()
}

/// Appends `src` facts into `dst`, preserving deterministic ordering.
fn merge_facts(dst: &mut Facts, src: &Facts) {
    dst.method_calls.extend(src.method_calls.iter().cloned());
    dst.function_calls
        .extend(src.function_calls.iter().cloned());
    dst.macros.extend(src.macros.iter().cloned());
    dst.strings.extend(src.strings.iter().cloned());
    dst.arith.extend(src.arith.iter().cloned());
    dst.modulo.extend(src.modulo.iter().cloned());
    dst.comparisons.extend(src.comparisons.iter().cloned());
    dst.client_calls.extend(src.client_calls.iter().cloned());
    dst.has_unsafe |= src.has_unsafe;
    dst.unsafe_locations
        .extend(src.unsafe_locations.iter().copied());
}

/// A contract entry point with its AST body attached.
pub struct ContractFn<'a> {
    /// Function name.
    pub name: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// Function body.
    pub block: &'a syn::Block,
    /// Whether the function is `pub`.
    pub is_public: bool,
    /// Names of the function's parameters, in declaration order.
    ///
    /// Only plain identifier patterns are recorded; destructuring patterns are
    /// deliberately omitted because they cannot be matched to a single name.
    pub params: Vec<String>,
}

/// Collects the simple identifier parameter names of a function signature.
fn parameter_names(sig: &syn::Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
                syn::Pat::Ident(pat_ident) => Some(pat_ident.ident.to_string()),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

/// Collects exported contract entry points (`pub fn` in `#[contractimpl]`).
///
/// Recurses into inline modules.
pub fn contract_entry_functions(file: &syn::File) -> Vec<ContractFn<'_>> {
    let mut out = Vec::new();
    collect_contract_fns(&file.items, &mut out);
    out
}

fn collect_contract_fns<'a>(items: &'a [syn::Item], out: &mut Vec<ContractFn<'a>>) {
    for item in items {
        match item {
            syn::Item::Impl(imp) => {
                let attrs: Vec<String> = imp.attrs.iter().map(attribute_path).collect();
                let is_contract_impl = attrs.iter().any(|a| {
                    matches!(
                        soroban::contract_attribute_strength(a),
                        Some(ContractAttrStrength::Definition)
                    )
                });
                if !is_contract_impl {
                    continue;
                }
                for impl_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = impl_item {
                        let (line, column) = span_line_col(&f.sig);
                        out.push(ContractFn {
                            name: f.sig.ident.to_string(),
                            line,
                            column,
                            block: &f.block,
                            is_public: matches!(f.vis, syn::Visibility::Public(_)),
                            params: parameter_names(&f.sig),
                        });
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, sub)) = &m.content {
                    collect_contract_fns(sub, out);
                }
            }
            _ => {}
        }
    }
}

/// Builds a source location for a fact inside a source file.
pub fn location_for(
    ctx: &AnalysisContext<'_>,
    source: &ParsedSource,
    line: usize,
    column: usize,
) -> SourceLocation {
    SourceLocation::with_column(ctx.relative_path(&source.path), line, column)
}

/// Returns true if a string looks like a Stellar strkey (account `G`/contract `C`).
pub fn looks_like_stellar_address(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 56 {
        return false;
    }
    let first = bytes[0];
    if first != b'G' && first != b'C' {
        return false;
    }
    value[1..]
        .bytes()
        .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_of(src: &str) -> Facts {
        let file = syn::parse_file(src).unwrap();
        facts_from_file(&file)
    }

    #[test]
    fn detects_storage_mutations() {
        let facts = facts_of("fn f(env: Env) { env.storage().persistent().set(&k, &v); }");
        let mutations = facts.storage_mutations();
        assert_eq!(mutations.len(), 1);
        assert_eq!(mutations[0].name, "set");
        assert_eq!(facts.persistent_mutations().len(), 1);
    }

    #[test]
    fn unrelated_set_is_not_storage_mutation() {
        let facts = facts_of("fn f(m: Map) { m.set(&k, &v); }");
        assert!(facts.storage_mutations().is_empty());
    }

    #[test]
    fn detects_require_auth() {
        let facts = facts_of("fn f(a: Address) { a.require_auth(); }");
        assert!(facts.has_require_auth());
    }

    #[test]
    fn detects_arithmetic_ops_and_ignores_non_arithmetic() {
        let facts = facts_of(
            "fn f(a: i128, b: i128) { let _ = a - b; let _ = a + b; let _ = a * b; let _ = a / b; let _ = a == b; }",
        );
        let ops: Vec<_> = facts
            .arithmetic_ops()
            .iter()
            .map(|f| f.op.as_str())
            .collect();
        assert_eq!(ops, vec!["-", "+", "*"]);
    }

    #[test]
    fn detects_modulo_comparisons_and_ledger_accesses() {
        let facts = facts_of(
            "fn f(env: Env) -> bool { env.ledger().timestamp() % 10 > 3 && env.ledger().sequence() == 7 }",
        );
        assert_eq!(facts.modulo.len(), 1);
        assert_eq!(facts.comparisons.len(), 2);
        let accesses: Vec<_> = facts
            .ledger_accesses()
            .iter()
            .map(|call| call.name.as_str())
            .collect();
        assert_eq!(accesses, vec!["timestamp", "sequence"]);
    }

    #[test]
    fn resolves_cross_contract_client_calls_in_source_order() {
        let facts = facts_of(
            "fn f(env: Env) { let client = TokenClient::new(&env, &id); client.transfer(&a, &b, &c); }",
        );
        let calls = facts.ordered_cross_contract_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "transfer");
        assert!(calls[0].start_byte > 0);
    }

    #[test]
    fn merges_intra_file_helper_facts() {
        let file = syn::parse_file(
            r#"
            #[contractimpl]
            impl C {
                pub fn set_value(env: Env, v: u32) {
                    Self::check(&env);
                    env.storage().persistent().set(&Key::V, &v);
                }
                fn check(env: &Env) { admin(env).require_auth(); }
            }
            "#,
        )
        .unwrap();
        let fns = contract_entry_functions(&file);
        let entry = fns.iter().find(|f| f.name == "set_value").unwrap();
        let facts = facts_with_helpers(&file, entry);
        assert!(facts.has_require_auth());
        assert_eq!(facts.persistent_mutations().len(), 1);
    }

    #[test]
    fn detects_panics() {
        let facts = facts_of("fn f() { let x = g().unwrap(); panic!(\"x\"); }");
        let panics = facts.panics();
        assert_eq!(panics.len(), 2);
    }

    #[test]
    fn detects_unsafe() {
        let facts = facts_of("fn f() { unsafe { g(); } }");
        assert!(facts.has_unsafe);
        assert_eq!(facts.unsafe_locations.len(), 1);
    }

    #[test]
    fn detects_cross_contract_constructor() {
        let facts = facts_of("fn f(env: Env) { let c = TokenClient::new(&env, &id); }");
        assert_eq!(facts.cross_contract_constructors().len(), 1);
    }

    #[test]
    fn validates_strkey_shape() {
        let good = format!("G{}", "A".repeat(55));
        assert!(looks_like_stellar_address(&good));
        let bad = format!("X{}", "A".repeat(55));
        assert!(!looks_like_stellar_address(&bad));
        assert!(!looks_like_stellar_address("too-short"));
    }

    #[test]
    fn finds_contract_entry_functions_only() {
        let file = syn::parse_file(
            r#"
            struct C;
            impl C { pub fn helper(&self) {} }
            #[contractimpl]
            impl X { pub fn entry() {} fn private() {} }
            "#,
        )
        .unwrap();
        let fns = contract_entry_functions(&file);
        assert_eq!(fns.len(), 2);
        let names: Vec<_> = fns.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"entry"));
        assert!(names.contains(&"private"));
        assert!(!names.contains(&"helper"));
    }
}
