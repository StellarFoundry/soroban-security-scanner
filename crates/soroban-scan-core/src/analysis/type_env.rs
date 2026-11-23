//! An immutable, span-aware type environment for rules.
//!
//! Type information is collected by the parser but was previously only visible
//! to the parser itself. This module records the syntactically visible type of
//! items, function parameters, and typed locals, keyed by the item name and the
//! span of its declaration.
//!
//! The environment performs no type inference. A name whose type is not written
//! in the source is recorded as [`TypeInfo::Unknown`], and every lookup for a
//! missing item or an out-of-scope span returns [`TypeInfo::Unknown`] instead of
//! panicking. Callers must treat unknown as "not known", never as a guess.
//!
//! Environments are built once per source file and shared read-only through the
//! [`AnalysisContext`](crate::context::AnalysisContext), so rule execution can
//! never mutate them.

use std::collections::BTreeMap;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::source::ParsedSource;

/// A 1-based source position used as the span part of a type key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpanKey {
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
}

impl SpanKey {
    /// Creates a span key.
    pub fn new(line: usize, column: usize) -> Self {
        SpanKey { line, column }
    }

    /// Returns the 1-based start position of a spanned node.
    pub fn start_of<T: Spanned>(node: &T) -> Self {
        let start = node.span().start();
        SpanKey::new(start.line, start.column + 1)
    }
}

/// The type information known for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeInfo {
    /// A type whose text is visible in the source.
    Known(String),
    /// No type was written for the item, or it cannot be determined locally.
    Unknown,
}

impl TypeInfo {
    /// Creates a known type entry.
    pub fn known(name: impl Into<String>) -> Self {
        TypeInfo::Known(name.into())
    }

    /// Whether this entry carries a visible type name.
    pub fn is_known(&self) -> bool {
        matches!(self, TypeInfo::Known(_))
    }

    /// The visible type name, if any.
    pub fn name(&self) -> Option<&str> {
        match self {
            TypeInfo::Known(name) => Some(name),
            TypeInfo::Unknown => None,
        }
    }
}

/// One declaration in the type environment.
///
/// `scope_end_line` is the last line on which the declaration is in scope. A
/// function parameter is in scope for the whole function body; a local is in
/// scope until the end of its enclosing block. Global items use
/// `usize::MAX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeEntry {
    /// The declared item name.
    pub item: String,
    /// The 1-based start position of the declaration.
    pub span: SpanKey,
    /// The last 1-based line on which the declaration is visible.
    pub scope_end_line: usize,
    /// The type information recorded for the declaration.
    pub info: TypeInfo,
}

/// An immutable map from `(item, span)` to [`TypeInfo`].
///
/// Declarations that share a name are kept separately. [`TypeEnvironment::lookup`]
/// resolves the innermost declaration visible at the queried span, so a shadowed
/// local is never confused with an earlier one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TypeEnvironment {
    entries: BTreeMap<(String, SpanKey), TypeEntry>,
}

impl TypeEnvironment {
    /// Creates an empty environment.
    pub fn new() -> Self {
        TypeEnvironment::default()
    }

    /// Builds an environment from a parsed source file.
    ///
    /// Sources without a syntax tree produce an empty environment.
    pub fn from_source(source: &ParsedSource) -> Self {
        match &source.syntax {
            Some(file) => TypeEnvironment::from_file(file),
            None => TypeEnvironment::new(),
        }
    }

    /// Builds an environment from a syntax tree.
    pub fn from_file(file: &syn::File) -> Self {
        let mut environment = TypeEnvironment::new();
        collect_item_types(&file.items, &mut environment);
        let mut visitor = TypeVisitor {
            environment: &mut environment,
            scopes: Vec::new(),
        };
        visitor.visit_file(file);
        environment
    }

    /// Inserts an entry, replacing an entry with the same item and span.
    pub fn insert(&mut self, entry: TypeEntry) {
        self.entries.insert((entry.item.clone(), entry.span), entry);
    }

    /// Iterates over entries in deterministic `(item, span)` order.
    pub fn entries(&self) -> impl Iterator<Item = &TypeEntry> {
        self.entries.values()
    }

    /// Returns the exact entry for an item declared at `span`, if present.
    pub fn get(&self, item: &str, span: SpanKey) -> Option<&TypeInfo> {
        self.entries
            .get(&(item.to_string(), span))
            .map(|entry| &entry.info)
    }

    /// Looks up the type of `item` visible at `span`.
    ///
    /// The innermost declaration that starts at or before `span` and whose scope
    /// contains the queried line wins. Missing items, out-of-scope declarations,
    /// and declarations without a written type all return [`TypeInfo::Unknown`].
    pub fn lookup(&self, item: &str, span: SpanKey) -> TypeInfo {
        let mut best: Option<&TypeEntry> = None;
        for entry in self.entries.values() {
            if entry.item != item {
                continue;
            }
            if entry.span > span || entry.scope_end_line < span.line {
                continue;
            }
            if best.is_none_or(|current| entry.span >= current.span) {
                best = Some(entry);
            }
        }
        best.map(|entry| entry.info.clone())
            .unwrap_or(TypeInfo::Unknown)
    }

    /// Convenience lookup by 1-based line and column.
    pub fn lookup_at(&self, item: &str, line: usize, column: usize) -> TypeInfo {
        self.lookup(item, SpanKey::new(line, column))
    }

    /// Number of declarations recorded.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the environment contains no declarations.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn collect_item_types(items: &[syn::Item], environment: &mut TypeEnvironment) {
    for item in items {
        let (name, span) = match item {
            syn::Item::Struct(item) => (Some(&item.ident), SpanKey::start_of(item)),
            syn::Item::Enum(item) => (Some(&item.ident), SpanKey::start_of(item)),
            syn::Item::Union(item) => (Some(&item.ident), SpanKey::start_of(item)),
            syn::Item::Type(item) => (Some(&item.ident), SpanKey::start_of(item)),
            syn::Item::Trait(item) => (Some(&item.ident), SpanKey::start_of(item)),
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_item_types(nested, environment);
                }
                (None, SpanKey::new(0, 0))
            }
            _ => (None, SpanKey::new(0, 0)),
        };
        if let Some(name) = name {
            let item = name.to_string();
            environment.insert(TypeEntry {
                item: item.clone(),
                span,
                scope_end_line: usize::MAX,
                info: TypeInfo::known(item),
            });
        }
    }
}

struct TypeVisitor<'a> {
    environment: &'a mut TypeEnvironment,
    scopes: Vec<usize>,
}

impl TypeVisitor<'_> {
    fn current_scope_end(&self) -> usize {
        self.scopes.last().copied().unwrap_or(usize::MAX)
    }

    fn record(&mut self, item: String, span: SpanKey, info: TypeInfo) {
        self.environment.insert(TypeEntry {
            item,
            span,
            scope_end_line: self.current_scope_end(),
            info,
        });
    }

    fn record_parameters(&mut self, signature: &syn::Signature, body: &syn::Block) {
        let scope_end_line = body.span().end().line;
        for argument in &signature.inputs {
            let syn::FnArg::Typed(typed) = argument else {
                continue;
            };
            let syn::Pat::Ident(pattern) = &*typed.pat else {
                continue;
            };
            self.environment.insert(TypeEntry {
                item: pattern.ident.to_string(),
                span: SpanKey::start_of(&*typed.pat),
                scope_end_line,
                info: TypeInfo::known(typed.ty.to_token_stream().to_string()),
            });
        }
    }
}

impl<'ast> Visit<'ast> for TypeVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.record_parameters(&node.sig, &node.block);
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.record_parameters(&node.sig, &node.block);
        visit::visit_impl_item_fn(self, node);
    }

    fn visit_block(&mut self, node: &'ast syn::Block) {
        self.scopes.push(node.span().end().line);
        visit::visit_block(self, node);
        self.scopes.pop();
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        match &node.pat {
            syn::Pat::Type(typed) => {
                if let syn::Pat::Ident(pattern) = &*typed.pat {
                    self.record(
                        pattern.ident.to_string(),
                        SpanKey::start_of(&*typed.pat),
                        TypeInfo::known(typed.ty.to_token_stream().to_string()),
                    );
                }
            }
            syn::Pat::Ident(pattern) => {
                // An unannotated local still shadows an earlier declaration.
                // Its type is unknown rather than inferred.
                self.record(
                    pattern.ident.to_string(),
                    SpanKey::start_of(&node.pat),
                    TypeInfo::Unknown,
                );
            }
            _ => {}
        }
        visit::visit_local(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn environment(source: &str) -> TypeEnvironment {
        let parsed = crate::source::parse_source(Path::new("src/lib.rs"), Path::new("."), source);
        TypeEnvironment::from_source(&parsed)
    }

    fn entry<'a>(environment: &'a TypeEnvironment, item: &str, ty: &str) -> &'a TypeEntry {
        environment
            .entries()
            .find(|entry| entry.item == item && entry.info.name() == Some(ty))
            .unwrap_or_else(|| panic!("missing {item}: {ty} entry"))
    }

    #[test]
    fn looks_up_parameters_and_locals() {
        let environment = environment(
            "fn f(amount: u32) {\n\
                 let limit: u64 = 1;\n\
                 let _ = (amount, limit);\n\
             }",
        );
        let amount = entry(&environment, "amount", "u32");
        assert_eq!(
            environment.lookup("amount", amount.span),
            TypeInfo::known("u32")
        );
        let limit = entry(&environment, "limit", "u64");
        assert_eq!(
            environment.lookup("limit", limit.span),
            TypeInfo::known("u64")
        );
    }

    #[test]
    fn shadowed_locals_resolve_to_the_innermost_declaration() {
        let environment = environment(
            "fn f() {\n\
                 let value: u32 = 1;\n\
                 {\n\
                     let value: u64 = 2;\n\
                     let _ = value;\n\
                 }\n\
                 let _ = value;\n\
             }",
        );
        let outer = entry(&environment, "value", "u32");
        let inner = entry(&environment, "value", "u64");

        assert_eq!(
            environment.lookup("value", inner.span),
            TypeInfo::known("u64")
        );
        assert_eq!(environment.lookup_at("value", 7, 5), TypeInfo::known("u32"));
        assert_eq!(
            environment.lookup("value", outer.span),
            TypeInfo::known("u32")
        );
    }

    #[test]
    fn untyped_shadowing_declaration_is_unknown() {
        let environment = environment(
            "fn f() {\n\
                 let value: u32 = 1;\n\
                 let value = 2;\n\
                 let _ = value;\n\
             }",
        );
        let shadow = environment
            .entries()
            .find(|entry| entry.item == "value" && entry.info == TypeInfo::Unknown)
            .expect("untyped shadow entry");
        assert_eq!(environment.lookup("value", shadow.span), TypeInfo::Unknown);
        assert_eq!(environment.lookup_at("value", 4, 5), TypeInfo::Unknown);
    }

    #[test]
    fn missing_entries_and_out_of_scope_lookups_return_unknown() {
        let environment = environment("fn f() {\n    let value: u32 = 1;\n}\n");
        assert_eq!(environment.lookup_at("missing", 2, 5), TypeInfo::Unknown);
        assert!(environment.get("value", SpanKey::new(99, 1)).is_none());
        assert_eq!(environment.lookup_at("value", 99, 1), TypeInfo::Unknown);
    }

    #[test]
    fn parses_fail_gracefully_with_an_empty_environment() {
        let parsed =
            crate::source::parse_source(Path::new("src/broken.rs"), Path::new("."), "fn broken( {");
        let environment = TypeEnvironment::from_source(&parsed);
        assert!(environment.is_empty());
        assert_eq!(environment.lookup_at("anything", 1, 1), TypeInfo::Unknown);
    }
}
