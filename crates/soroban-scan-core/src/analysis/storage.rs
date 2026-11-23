//! Bounded resolution of `Map` types read from or written to contract storage.
//!
//! Storage checks such as `SS-016` need to know whether a stored map's key is a
//! small, bounded SDK type (`Symbol`, `Address`, or a tuple of them) or something
//! the analysis cannot classify. Only syntactically visible types are resolved:
//! a storage turbofish (`get::<_, Map<K, V>>`) or a typed local initialized from
//! a storage read. Everything else is reported as [`MapKeyType::Unknown`], never
//! assumed bounded.

use std::collections::BTreeSet;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::rules::util::ContractFn;

/// Maximum number of map storage accesses retained per function.
pub const MAX_MAP_ACCESSES: usize = 64;
/// Maximum rendered value type length.
pub const MAX_VALUE_TYPE_LEN: usize = 96;
/// Maximum tuple elements classified for a composite key.
pub const MAX_TUPLE_ELEMENTS: usize = 8;

/// A map key type as far as the source makes it visible.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum MapKeyType {
    /// `Symbol` key, short and bounded by the SDK.
    Symbol,
    /// `Address` key.
    Address,
    /// A tuple of classified keys.
    Tuple(Vec<MapKeyType>),
    /// Not visible, not an SDK key type, or too complex to classify.
    Unknown,
}

impl MapKeyType {
    /// Stable lowercase label used in evidence and documentation.
    pub fn label(&self) -> String {
        match self {
            MapKeyType::Symbol => "symbol".to_string(),
            MapKeyType::Address => "address".to_string(),
            MapKeyType::Tuple(elements) => format!(
                "({})",
                elements
                    .iter()
                    .map(MapKeyType::label)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            MapKeyType::Unknown => "unknown".to_string(),
        }
    }

    /// True when the key type could not be classified.
    pub fn is_unknown(&self) -> bool {
        matches!(self, MapKeyType::Unknown)
    }
}

/// One visible `Map` storage access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapStorageAccess {
    /// Classified key type.
    pub key_type: MapKeyType,
    /// Rendered value type, when visible.
    pub value_type: String,
    /// Storage method (`get`, `get_unchecked`, `set`, `update`, `remove`).
    pub method: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// Rendered access text (bounded).
    pub text: String,
}

/// Resolves the `Map` key and value types visible in a function body.
///
/// Only storage methods whose value type is syntactically a `Map` produce an
/// access. Results are deterministic, de-duplicated, and bounded by
/// [`MAX_MAP_ACCESSES`].
pub fn map_storage_accesses(block: &syn::Block) -> Vec<MapStorageAccess> {
    let mut visitor = AccessVisitor::default();
    visitor.visit_block(block);
    let mut accesses = visitor.accesses;
    accesses.sort_by(|a, b| {
        (
            a.line,
            a.column,
            a.method.as_str(),
            &a.key_type,
            a.value_type.as_str(),
        )
            .cmp(&(
                b.line,
                b.column,
                b.method.as_str(),
                &b.key_type,
                b.value_type.as_str(),
            ))
    });
    accesses.dedup_by(|a, b| {
        (
            a.line,
            a.column,
            a.method.as_str(),
            &a.key_type,
            a.value_type.as_str(),
        ) == (
            b.line,
            b.column,
            b.method.as_str(),
            &b.key_type,
            b.value_type.as_str(),
        )
    });
    accesses.truncate(MAX_MAP_ACCESSES);
    accesses
}

/// Convenience wrapper for a contract entry point.
pub fn map_accesses_for_entry(entry: &ContractFn<'_>) -> Vec<MapStorageAccess> {
    map_storage_accesses(entry.block)
}

#[derive(Default)]
struct AccessVisitor {
    /// Locals that hold a storage handle (`let store = env.storage()...`).
    storage_handles: BTreeSet<String>,
    accesses: Vec<MapStorageAccess>,
}

impl AccessVisitor {
    fn push(
        &mut self,
        method: &str,
        key_type: MapKeyType,
        value_type: String,
        line: usize,
        column: usize,
        text: &str,
    ) {
        if self.accesses.len() >= MAX_MAP_ACCESSES {
            return;
        }
        self.accesses.push(MapStorageAccess {
            key_type,
            value_type,
            method: method.to_string(),
            line,
            column,
            text: truncate(text, 160),
        });
    }

    fn is_storage_receiver(&self, receiver: &syn::Expr) -> bool {
        if let syn::Expr::Path(path) = receiver {
            if let Some(ident) = path.path.get_ident() {
                if self.storage_handles.contains(&ident.to_string()) {
                    return true;
                }
            }
        }
        receiver
            .to_token_stream()
            .to_string()
            .to_ascii_lowercase()
            .contains("storage")
    }
}

impl<'ast> Visit<'ast> for AccessVisitor {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let Some(init) = &node.init {
            let init_text = init.expr.to_token_stream().to_string().to_ascii_lowercase();
            let from_storage = init_text.contains("storage");
            match &node.pat {
                syn::Pat::Ident(pattern) => {
                    if from_storage {
                        self.storage_handles.insert(pattern.ident.to_string());
                    }
                }
                syn::Pat::Type(typed) => {
                    if let syn::Pat::Ident(pattern) = &*typed.pat {
                        if from_storage {
                            // A typed `Map` local is data, not a storage handle.
                            if let Some((key_type, value_type)) = map_types(&typed.ty) {
                                let start = typed.ty.span().start();
                                self.push(
                                    "local",
                                    key_type,
                                    value_type,
                                    start.line,
                                    start.column + 1,
                                    &typed.ty.to_token_stream().to_string(),
                                );
                            } else {
                                self.storage_handles.insert(pattern.ident.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let is_storage = self.is_storage_receiver(&node.receiver);
        if is_storage
            && matches!(
                method.as_str(),
                "get" | "get_unchecked" | "set" | "update" | "remove"
            )
        {
            let mut map = None;
            if let Some(turbofish) = &node.turbofish {
                for argument in turbofish.args.iter().rev() {
                    if let syn::GenericArgument::Type(ty) = argument {
                        if let Some(types) = map_types(ty) {
                            map = Some(types);
                            break;
                        }
                    }
                }
            }
            if let Some((key_type, value_type)) = map {
                let start = node.span().start();
                self.push(
                    &method,
                    key_type,
                    value_type,
                    start.line,
                    start.column + 1,
                    &node.to_token_stream().to_string(),
                );
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

/// Extracts `(key, value)` types from a `Map<K, V>` type.
fn map_types(ty: &syn::Type) -> Option<(MapKeyType, String)> {
    let ty = strip_reference(ty);
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Map" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    let types: Vec<&syn::Type> = arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            syn::GenericArgument::Type(ty) => Some(ty),
            _ => None,
        })
        .collect();
    if types.len() != 2 {
        return None;
    }
    Some((
        classify_key(types[0]),
        truncate(&types[1].to_token_stream().to_string(), MAX_VALUE_TYPE_LEN),
    ))
}

fn strip_reference(ty: &syn::Type) -> &syn::Type {
    match ty {
        syn::Type::Reference(reference) => strip_reference(&reference.elem),
        syn::Type::Group(group) => strip_reference(&group.elem),
        syn::Type::Paren(paren) => strip_reference(&paren.elem),
        other => other,
    }
}

fn classify_key(ty: &syn::Type) -> MapKeyType {
    let ty = strip_reference(ty);
    match ty {
        syn::Type::Tuple(tuple) => {
            if tuple.elems.is_empty() || tuple.elems.len() > MAX_TUPLE_ELEMENTS {
                return MapKeyType::Unknown;
            }
            MapKeyType::Tuple(tuple.elems.iter().map(classify_key).collect())
        }
        syn::Type::Path(path) => {
            let Some(segment) = path.path.segments.last() else {
                return MapKeyType::Unknown;
            };
            match segment.ident.to_string().as_str() {
                "Symbol" => MapKeyType::Symbol,
                "Address" => MapKeyType::Address,
                _ => MapKeyType::Unknown,
            }
        }
        _ => MapKeyType::Unknown,
    }
}

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

    fn accesses(source: &str) -> Vec<MapStorageAccess> {
        let file = syn::parse_file(source).expect("test source must parse");
        let syn::Item::Fn(function) = &file.items[0] else {
            panic!("expected a function");
        };
        map_storage_accesses(&function.block)
    }

    #[test]
    fn resolves_symbol_keys_from_storage_turbofish() {
        let found = accesses(
            r#"
            fn f(env: Env) {
                let map: Map<Symbol, u32> = env.storage().persistent().get::<_, Map<Symbol, u32>>(&K).unwrap();
                let _ = map;
            }
            "#,
        );
        let access = found.iter().find(|access| access.method == "get").unwrap();
        assert_eq!(access.key_type, MapKeyType::Symbol);
        assert_eq!(access.value_type, "u32");
    }

    #[test]
    fn resolves_address_and_tuple_keys() {
        let found = accesses(
            r#"
            fn f(env: Env) {
                let by_address: Map<Address, i128> = env.storage().persistent().get::<_, Map<Address, i128>>(&A).unwrap();
                let by_tuple: Map<(Symbol, Address), u64> = env.storage().instance().get::<_, Map<(Symbol, Address), u64>>(&B).unwrap();
                let _ = (by_address, by_tuple);
            }
            "#,
        );
        assert!(found
            .iter()
            .any(|access| access.key_type == MapKeyType::Address));
        assert!(found.iter().any(|access| access.key_type
            == MapKeyType::Tuple(vec![MapKeyType::Symbol, MapKeyType::Address])));
    }

    #[test]
    fn unknown_keys_are_marked_unknown() {
        let found = accesses(
            r#"
            fn f(env: Env) {
                let map: Map<CustomKey, u32> = env.storage().persistent().get::<_, Map<CustomKey, u32>>(&K).unwrap();
                let _ = map;
            }
            "#,
        );
        let access = found.first().expect("map access");
        assert!(access.key_type.is_unknown());
        assert_eq!(access.key_type.label(), "unknown");
    }

    #[test]
    fn non_map_storage_accesses_are_not_reported() {
        let found = accesses(
            r#"
            fn f(env: Env) {
                let value: u64 = env.storage().persistent().get::<_, u64>(&K).unwrap();
                env.storage().persistent().set(&K, &value);
            }
            "#,
        );
        assert!(found.is_empty());
    }

    #[test]
    fn aliased_storage_handle_is_followed() {
        let found = accesses(
            r#"
            fn f(env: Env) {
                let store = env.storage().persistent();
                let map: Map<Symbol, u32> = store.get::<_, Map<Symbol, u32>>(&K).unwrap();
                let _ = map;
            }
            "#,
        );
        assert!(found
            .iter()
            .any(|access| access.key_type == MapKeyType::Symbol));
    }
}
