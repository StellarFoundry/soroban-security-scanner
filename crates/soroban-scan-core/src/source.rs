//! Rust source parsing and item inventory.
//!
//! Parsing uses [`syn`] and never executes code. Source spans are captured with
//! `proc-macro2` span locations so findings can cite exact lines and columns.
//! A file that fails to parse is recorded as a diagnostic rather than aborting
//! the scan.

use std::borrow::Cow;
use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::Visit;

use crate::error::ScanError;
use crate::model::{Diagnostic, DiagnosticCode, Project, SorobanInfo};
use crate::soroban::{self, ContractAttrStrength};

/// Maximum source file size that will be read (8 MiB).
pub const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

/// Kinds of top-level items the inventory recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemKind {
    /// `fn`
    Function,
    /// `impl`
    Impl,
    /// `trait`
    Trait,
    /// `struct`
    Struct,
    /// `enum`
    Enum,
    /// `union`
    Union,
    /// `const`
    Const,
    /// `static`
    Static,
    /// `mod`
    Module,
    /// A macro invocation item.
    Macro,
    /// `type`
    TypeAlias,
    /// `use`
    Use,
    /// `extern` block.
    ForeignMod,
    /// Anything else.
    Other,
}

impl ItemKind {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            ItemKind::Function => "function",
            ItemKind::Impl => "impl",
            ItemKind::Trait => "trait",
            ItemKind::Struct => "struct",
            ItemKind::Enum => "enum",
            ItemKind::Union => "union",
            ItemKind::Const => "const",
            ItemKind::Static => "static",
            ItemKind::Module => "module",
            ItemKind::Macro => "macro",
            ItemKind::TypeAlias => "type_alias",
            ItemKind::Use => "use",
            ItemKind::ForeignMod => "foreign_mod",
            ItemKind::Other => "other",
        }
    }
}

/// Kind of a Soroban contract type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContractTypeKind {
    /// A struct annotated with `#[contracttype]`.
    Struct,
    /// An enum annotated with `#[contracttype]` or `#[contracterror]`.
    Enum,
}

impl ContractTypeKind {
    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            ContractTypeKind::Struct => "struct",
            ContractTypeKind::Enum => "enum",
        }
    }
}

/// A struct or enum that participates in the contract's serialized interface.
///
/// Types annotated with `#[contracttype]` define stored and transported data,
/// while `#[contracterror]` enums define the contract's error variants. Both are
/// kept separate from function facts because detectors need the data model
/// independently of any function body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractTypeSummary {
    /// Type name.
    pub name: String,
    /// Whether the declaration is a struct or an enum.
    pub kind: ContractTypeKind,
    /// Declared visibility (`pub`).
    pub is_public: bool,
    /// Attribute path strings (for example `contracttype`).
    pub attributes: Vec<String>,
    /// Variant names for enums; empty for structs.
    pub variants: Vec<String>,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// 1-based end line.
    pub end_line: usize,
}

/// A function parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamSummary {
    /// Parameter binding name (or rendered pattern).
    pub name: String,
    /// Rendered parameter type.
    pub ty: String,
}

/// Declared visibility of a function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Visibility {
    /// Declared `pub`, visible outside the crate.
    Public,
    /// Declared `pub(crate)`, visible within the crate.
    Crate,
    /// Declared `pub(super)`, visible to the parent module.
    Super,
    /// Declared `pub(self)`, visible to the current module.
    Self_,
    /// No visibility modifier (private to the module).
    #[default]
    Inherited,
}

impl Visibility {
    /// Whether this is true `pub` visibility.
    pub fn is_public(self) -> bool {
        self == Visibility::Public
    }

    /// Stable lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Crate => "crate",
            Visibility::Super => "super",
            Visibility::Self_ => "self",
            Visibility::Inherited => "inherited",
        }
    }
}

/// Summary of a function definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionSummary {
    /// Unqualified function name.
    pub name: String,
    /// Name qualified by any enclosing module and impl/trait.
    pub qualified_name: String,
    /// 1-based line of the function.
    pub line: usize,
    /// 1-based column of the function.
    pub column: usize,
    /// 1-based end line of the function.
    pub end_line: usize,
    /// Declared visibility.
    pub visibility: Visibility,
    /// Whether the function is `async`.
    pub is_async: bool,
    /// Attribute path strings on the function.
    pub attributes: Vec<String>,
    /// Joined doc-comment text attached to this function (`///`, `/** ... */`,
    /// or `#[doc = "..."]`), if any.
    pub doc: String,
    /// Parameters.
    pub params: Vec<ParamSummary>,
    /// Rendered return type, if not `()`.
    pub return_type: Option<String>,
    /// Enclosing impl/trait name, if any.
    pub in_impl: Option<String>,
    /// Rendered trait path when the function is defined in a trait impl.
    ///
    /// Inherent impl methods and free functions have `None`. Trait
    /// definitions also have `None` because their methods are not bound to a
    /// concrete implementing type.
    pub trait_path: Option<String>,
    /// Attribute path strings on the enclosing impl block.
    pub impl_attributes: Vec<String>,
    /// True when the function is a `const fn`.
    pub is_const: bool,
    /// True when the function is an exported contract entry point
    /// (`pub fn` inside a `#[contractimpl]` block).
    pub is_contract_entry_point: bool,
    /// Raw token text of each `#[cfg(...)]` predicate on the function, for
    /// example `test` or `feature = "x"`. Recorded, never evaluated.
    pub cfg_attrs: Vec<String>,
}

/// Summary of a non-function item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemSummary {
    /// Item kind.
    pub kind: ItemKind,
    /// Item name (may be a rendered type for impls).
    pub name: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// 1-based end line.
    pub end_line: usize,
    /// Whether the item is `pub`.
    pub is_public: bool,
    /// Rendered trait path for `impl Trait for Type` blocks, if any.
    pub trait_path: Option<String>,
    /// Attribute path strings.
    pub attributes: Vec<String>,
    /// Joined doc-comment text attached to this item (`///`, `/** ... */`, or
    /// `#[doc = "..."]`), if any.
    pub doc: String,
    /// Raw token text of each `#[cfg(...)]` predicate on the item. Recorded,
    /// never evaluated.
    pub cfg_attrs: Vec<String>,
}

/// A `macro_rules!` definition found in a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroDefinition {
    /// Macro name.
    pub name: String,
    /// 1-based line of the definition.
    pub line: usize,
    /// 1-based column of the definition.
    pub column: usize,
    /// 1-based end line of the definition.
    pub end_line: usize,
}

/// A macro invocation found in a source file.
///
/// Invocations are recorded as written. They are never expanded or resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroInvocation {
    /// Path as written, for example `helper` or `foo::bar`.
    pub name: String,
    /// 1-based line of the invocation.
    pub line: usize,
    /// 1-based column of the invocation.
    pub column: usize,
    /// 1-based end line of the invocation.
    pub end_line: usize,
}

/// Kind of a generated-code marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedMarkerKind {
    /// A `@generated` marker inside a comment.
    GeneratedComment,
    /// An `include!` invocation.
    IncludeMacro,
}

impl GeneratedMarkerKind {
    /// Stable lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            GeneratedMarkerKind::GeneratedComment => "generated_comment",
            GeneratedMarkerKind::IncludeMacro => "include_macro",
        }
    }
}

/// A lexical generated-code marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedMarker {
    /// Marker kind.
    pub kind: GeneratedMarkerKind,
    /// 1-based line where the marker occurs.
    pub line: usize,
    /// 1-based column where the marker occurs.
    pub column: usize,
}

/// Kind of a const/static value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// `const`.
    Const,
    /// `static`.
    Static,
    /// `static mut`.
    StaticMut,
}

impl ValueKind {
    /// Stable lowercase label.
    pub fn as_str(self) -> &'static str {
        match self {
            ValueKind::Const => "const",
            ValueKind::Static => "static",
            ValueKind::StaticMut => "static_mut",
        }
    }
}

/// A `const` or `static` value.
///
/// The initializer is rendered as source text and is **never evaluated**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstSummary {
    /// Value kind.
    pub kind: ValueKind,
    /// Unqualified name.
    pub name: String,
    /// Name qualified by any enclosing module and impl/trait.
    pub qualified_name: String,
    /// Rendered declared type.
    pub ty: String,
    /// Rendered initializer expression.
    pub value: String,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// 1-based end line.
    pub end_line: usize,
    /// Declared visibility.
    pub visibility: Visibility,
    /// Attribute path strings.
    pub attributes: Vec<String>,
}

/// A parsed Rust source file.
pub struct ParsedSource {
    /// File path.
    pub path: PathBuf,
    /// Logical module path (best effort).
    pub module_path: String,
    /// Parsed syntax tree, if parsing succeeded.
    pub syntax: Option<syn::File>,
    /// Parse error message, if parsing failed.
    pub parse_error: Option<String>,
    /// Non-function items.
    pub items: Vec<ItemSummary>,
    /// Function definitions.
    pub functions: Vec<FunctionSummary>,
    /// `const` and `static` values.
    pub constants: Vec<ConstSummary>,
    /// `macro_rules!` definitions.
    pub macro_definitions: Vec<MacroDefinition>,
    /// Macro invocations, recorded without expansion.
    pub macro_invocations: Vec<MacroInvocation>,
    /// Lexical generated-code markers.
    pub generated_markers: Vec<GeneratedMarker>,
    /// `#[contracttype]`/`#[contracterror]` structs and enums.
    pub contract_types: Vec<ContractTypeSummary>,
    /// Locations of contract definitions, formatted as `path:line`.
    pub contract_definitions: Vec<String>,
    /// Inline suppression directives detected in the file.
    pub suppressions: Vec<crate::suppression::Suppression>,
    /// Best-effort import map built from this file's `use` items.
    pub imports: crate::imports::ImportMap,
}

impl ParsedSource {
    /// Returns true if the file parsed successfully.
    pub fn is_parsed(&self) -> bool {
        self.syntax.is_some()
    }

    /// Returns true when a generated-code marker or `include!` was found.
    pub fn is_generated(&self) -> bool {
        !self.generated_markers.is_empty()
    }

    /// Returns functions that are Soroban contract entry points.
    pub fn contract_entry_points(&self) -> impl Iterator<Item = &FunctionSummary> {
        self.functions.iter().filter(|f| f.is_contract_entry_point)
    }

    /// Canonicalizes a rendered path against this file's imports.
    ///
    /// Resolution is best-effort and syntactic: it understands `use` aliases,
    /// grouped imports, and globs, but never resolves across modules or crates.
    /// Ambiguous glob matches are returned as [`crate::imports::Resolution::Ambiguous`]
    /// rather than guessed.
    pub fn resolve_path(&self, path: &str) -> crate::imports::Resolution {
        self.imports.resolve(path)
    }

    /// Canonicalizes a path when exactly one import matches; otherwise returns
    /// the path unchanged.
    pub fn canonical_path(&self, path: &str) -> String {
        self.imports.canonicalize(path)
    }
}

/// Extracts the attribute path (for example `contractimpl`) as a string.
pub fn attribute_path(attr: &syn::Attribute) -> String {
    attr.path()
        .segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

/// Extracts the raw predicate tokens of every `#[cfg(...)]` attribute.
///
/// The tokens are recorded verbatim; the expression is never evaluated.
fn cfg_attr_tokens(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs
        .iter()
        .filter(|attr| attribute_path(attr) == "cfg")
        .filter_map(|attr| match &attr.meta {
            syn::Meta::List(list) => Some(list.tokens.to_string()),
            _ => None,
        })
        .collect()
}

fn attribute_paths(attrs: &[syn::Attribute]) -> Vec<String> {
    attrs.iter().map(attribute_path).collect()
}

/// Joins the doc comments attached to an inventoried item.
///
/// Rust stores doc comments as `#[doc = " ..."]` attributes, so `///`,
/// `/** ... */` and `#[doc = "..."]` are read identically here. Each attribute
/// is split on newlines so multi-line block comments are preserved. One leading
/// space (the conventional doc-comment margin) is removed per line, and the
/// outer blank lines are trimmed. A block comment keeps its `*` gutter
/// verbatim, because only the space before it is removed.
///
/// Scope: only the attributes of the inventoried item are read. A file-level
/// inner comment (`//!`, or `/*! ... */`, at the top of a file) is an inner
/// attribute of the *file* rather than of any item, so `syn` keeps it in
/// `syn::File::attrs`; it is reachable through [`ParsedSource::syntax`] and is
/// never reported as an item's `doc`. An inner comment inside a `mod` body
/// belongs to that module, so it is reported on the module item.
fn doc_comments(attrs: &[syn::Attribute]) -> String {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        let syn::Meta::NameValue(name_value) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(text),
            ..
        }) = &name_value.value
        else {
            continue;
        };
        for line in text.value().split('\n') {
            lines.push(line.strip_prefix(' ').unwrap_or(line).to_string());
        }
    }
    lines.join("\n").trim().to_string()
}

fn vis_is_public(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// Maps a `syn` visibility onto the scanner's visibility enum.
///
/// Other restricted forms such as `pub(in path)` are treated as crate-visible
/// for entry-point purposes: only true `pub` is exported.
fn visibility_of(vis: &syn::Visibility) -> Visibility {
    match vis {
        syn::Visibility::Public(_) => Visibility::Public,
        syn::Visibility::Restricted(restricted) => {
            if restricted.path.is_ident("crate") {
                Visibility::Crate
            } else if restricted.path.is_ident("super") {
                Visibility::Super
            } else if restricted.path.is_ident("self") {
                Visibility::Self_
            } else {
                Visibility::Crate
            }
        }
        syn::Visibility::Inherited => Visibility::Inherited,
    }
}

fn span_start<T: Spanned>(node: &T) -> (usize, usize) {
    let start = node.span().start();
    (start.line, start.column + 1)
}

fn span_end_line<T: Spanned>(node: &T) -> usize {
    node.span().end().line
}

fn pat_name(pat: &syn::Pat) -> String {
    match pat {
        syn::Pat::Ident(pi) => pi.ident.to_string(),
        other => other.to_token_stream().to_string(),
    }
}

/// Renders a type as source text.
///
/// Shared by function parameters, return types, and const/static declarations so
/// every inventory entry uses the same deterministic representation.
fn render_type(ty: &syn::Type) -> String {
    ty.to_token_stream().to_string()
}

fn params_of(sig: &syn::Signature) -> Vec<ParamSummary> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Receiver(_) => None,
            syn::FnArg::Typed(pt) => Some(ParamSummary {
                name: pat_name(&pt.pat),
                ty: render_type(&pt.ty),
            }),
        })
        .collect()
}

fn return_of(sig: &syn::Signature) -> Option<String> {
    match &sig.output {
        syn::ReturnType::Default => None,
        syn::ReturnType::Type(_, ty) => Some(render_type(ty)),
    }
}

fn record_contract_attrs(
    attrs: &[syn::Attribute],
    path: &Path,
    line: usize,
    out: &mut Vec<String>,
) {
    for attr in attrs {
        let attr_path = attribute_path(attr);
        if let Some(ContractAttrStrength::Definition) =
            soroban::contract_attribute_strength(&attr_path)
        {
            let location = format!("{}:{}", path.display(), line);
            if !out.contains(&location) {
                out.push(location);
            }
        }
    }
}

struct ImplContext {
    name: String,
    trait_path: Option<String>,
    attributes: Vec<String>,
}

fn qualified_name(name: &str, prefix: &str, impl_ctx: Option<&ImplContext>) -> String {
    match impl_ctx {
        Some(ctx) if prefix.is_empty() => format!("{}::{}", ctx.name, name),
        Some(ctx) => format!("{}::{}::{}", prefix, ctx.name, name),
        None if prefix.is_empty() => name.to_string(),
        None => format!("{prefix}::{name}"),
    }
}

fn make_function(
    sig: &syn::Signature,
    attrs: &[syn::Attribute],
    visibility: Visibility,
    prefix: &str,
    impl_ctx: Option<&ImplContext>,
) -> FunctionSummary {
    let name = sig.ident.to_string();
    let qualified_name = qualified_name(&name, prefix, impl_ctx);
    let impl_attributes = impl_ctx.map(|c| c.attributes.clone()).unwrap_or_default();
    let is_contract_entry_point = visibility.is_public()
        && impl_attributes.iter().any(|a| {
            matches!(
                soroban::contract_attribute_strength(a),
                Some(ContractAttrStrength::Definition)
            )
        });
    let (line, column) = span_start(sig);
    FunctionSummary {
        name,
        qualified_name,
        line,
        column,
        end_line: span_end_line(sig),
        visibility,
        is_async: sig.asyncness.is_some(),
        attributes: attribute_paths(attrs),
        doc: doc_comments(attrs),
        params: params_of(sig),
        return_type: return_of(sig),
        in_impl: impl_ctx.map(|c| c.name.clone()),
        trait_path: impl_ctx.and_then(|c| c.trait_path.clone()),
        impl_attributes,
        is_const: sig.constness.is_some(),
        is_contract_entry_point,
        cfg_attrs: cfg_attr_tokens(attrs),
    }
}

#[allow(clippy::too_many_arguments)]
fn make_const(
    kind: ValueKind,
    name: &syn::Ident,
    ty: &syn::Type,
    value: Option<&syn::Expr>,
    attrs: &[syn::Attribute],
    visibility: Visibility,
    prefix: &str,
    impl_ctx: Option<&ImplContext>,
    span: (usize, usize, usize),
) -> ConstSummary {
    let name = name.to_string();
    ConstSummary {
        kind,
        qualified_name: qualified_name(&name, prefix, impl_ctx),
        name,
        ty: render_type(ty),
        value: value
            .map(|expr| expr.to_token_stream().to_string())
            .unwrap_or_default(),
        line: span.0,
        column: span.1,
        end_line: span.2,
        visibility,
        attributes: attribute_paths(attrs),
    }
}

#[allow(clippy::too_many_arguments)]
fn walk_items(
    items: &[syn::Item],
    prefix: &str,
    impl_ctx: Option<&ImplContext>,
    file: &Path,
    out_items: &mut Vec<ItemSummary>,
    out_functions: &mut Vec<FunctionSummary>,
    out_constants: &mut Vec<ConstSummary>,
    out_contract_types: &mut Vec<ContractTypeSummary>,
    out_contract: &mut Vec<String>,
) {
    for item in items {
        let attrs = item_attrs(item);
        let (line, column) = span_start(item);
        let end_line = span_end_line(item);
        record_contract_attrs(&attrs, file, line, out_contract);

        match item {
            syn::Item::Fn(f) => {
                out_items.push(item_summary(
                    ItemKind::Function,
                    f.sig.ident.to_string(),
                    &attrs,
                    vis_is_public(&f.vis),
                    (line, column, end_line),
                ));
                out_functions.push(make_function(
                    &f.sig,
                    &attrs,
                    visibility_of(&f.vis),
                    prefix,
                    impl_ctx,
                ));
            }
            syn::Item::Impl(imp) => {
                let name = imp.self_ty.to_token_stream().to_string();
                let trait_path = imp
                    .trait_
                    .as_ref()
                    .map(|(path, _)| path.to_token_stream().to_string());
                let mut summary = item_summary(
                    ItemKind::Impl,
                    name.clone(),
                    &attrs,
                    false,
                    (line, column, end_line),
                );
                summary.trait_path = trait_path.clone();
                out_items.push(summary);
                let ctx = ImplContext {
                    name,
                    trait_path,
                    attributes: attribute_paths(&attrs),
                };
                for impl_item in &imp.items {
                    match impl_item {
                        syn::ImplItem::Fn(f) => {
                            let f_attrs = f.attrs.clone();
                            let (fl, fc) = span_start(&f.sig);
                            let fe = span_end_line(&f.sig);
                            out_items.push(item_summary(
                                ItemKind::Function,
                                f.sig.ident.to_string(),
                                &f_attrs,
                                vis_is_public(&f.vis),
                                (fl, fc, fe),
                            ));
                            out_functions.push(make_function(
                                &f.sig,
                                &f_attrs,
                                visibility_of(&f.vis),
                                prefix,
                                Some(&ctx),
                            ));
                        }
                        syn::ImplItem::Const(c) => {
                            let (cl, cc) = span_start(c);
                            out_items.push(item_summary(
                                ItemKind::Const,
                                c.ident.to_string(),
                                &c.attrs,
                                vis_is_public(&c.vis),
                                (cl, cc, span_end_line(c)),
                            ));
                            out_constants.push(make_const(
                                ValueKind::Const,
                                &c.ident,
                                &c.ty,
                                Some(&c.expr),
                                &c.attrs,
                                visibility_of(&c.vis),
                                prefix,
                                Some(&ctx),
                                (cl, cc, span_end_line(c)),
                            ));
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Trait(tr) => {
                let name = tr.ident.to_string();
                out_items.push(item_summary(
                    ItemKind::Trait,
                    name.clone(),
                    &attrs,
                    vis_is_public(&tr.vis),
                    (line, column, end_line),
                ));
                let ctx = ImplContext {
                    name,
                    trait_path: None,
                    attributes: attribute_paths(&attrs),
                };
                for trait_item in &tr.items {
                    match trait_item {
                        syn::TraitItem::Fn(f) => {
                            let f_attrs = f.attrs.clone();
                            out_functions.push(make_function(
                                &f.sig,
                                &f_attrs,
                                Visibility::Inherited,
                                prefix,
                                Some(&ctx),
                            ));
                        }
                        syn::TraitItem::Const(c) => {
                            let (cl, cc) = span_start(c);
                            out_constants.push(make_const(
                                ValueKind::Const,
                                &c.ident,
                                &c.ty,
                                c.default.as_ref().map(|(_, expr)| expr),
                                &c.attrs,
                                Visibility::Inherited,
                                prefix,
                                Some(&ctx),
                                (cl, cc, span_end_line(c)),
                            ));
                        }
                        _ => {}
                    }
                }
            }
            syn::Item::Mod(m) => {
                let name = m.ident.to_string();
                out_items.push(item_summary(
                    ItemKind::Module,
                    name.clone(),
                    &attrs,
                    vis_is_public(&m.vis),
                    (line, column, end_line),
                ));
                if let Some((_, sub_items)) = &m.content {
                    let child_prefix = if prefix.is_empty() {
                        name
                    } else {
                        format!("{prefix}::{name}")
                    };
                    walk_items(
                        sub_items,
                        &child_prefix,
                        None,
                        file,
                        out_items,
                        out_functions,
                        out_constants,
                        out_contract_types,
                        out_contract,
                    );
                }
            }
            syn::Item::Struct(s) => {
                out_items.push(item_summary(
                    ItemKind::Struct,
                    s.ident.to_string(),
                    &attrs,
                    vis_is_public(&s.vis),
                    (line, column, end_line),
                ));
                if has_contract_type_attr(&attrs) {
                    out_contract_types.push(contract_type_summary(
                        s.ident.to_string(),
                        ContractTypeKind::Struct,
                        &attrs,
                        vis_is_public(&s.vis),
                        Vec::new(),
                        (line, column, end_line),
                    ));
                }
            }
            syn::Item::Enum(e) => {
                out_items.push(item_summary(
                    ItemKind::Enum,
                    e.ident.to_string(),
                    &attrs,
                    vis_is_public(&e.vis),
                    (line, column, end_line),
                ));
                if has_contract_type_attr(&attrs) {
                    let variants = e.variants.iter().map(|v| v.ident.to_string()).collect();
                    out_contract_types.push(contract_type_summary(
                        e.ident.to_string(),
                        ContractTypeKind::Enum,
                        &attrs,
                        vis_is_public(&e.vis),
                        variants,
                        (line, column, end_line),
                    ));
                }
            }
            syn::Item::Union(u) => out_items.push(item_summary(
                ItemKind::Union,
                u.ident.to_string(),
                &attrs,
                vis_is_public(&u.vis),
                (line, column, end_line),
            )),
            syn::Item::Const(c) => {
                out_items.push(item_summary(
                    ItemKind::Const,
                    c.ident.to_string(),
                    &attrs,
                    vis_is_public(&c.vis),
                    (line, column, end_line),
                ));
                out_constants.push(make_const(
                    ValueKind::Const,
                    &c.ident,
                    &c.ty,
                    Some(&c.expr),
                    &attrs,
                    visibility_of(&c.vis),
                    prefix,
                    impl_ctx,
                    (line, column, end_line),
                ));
            }
            syn::Item::Static(s) => {
                out_items.push(item_summary(
                    ItemKind::Static,
                    s.ident.to_string(),
                    &attrs,
                    vis_is_public(&s.vis),
                    (line, column, end_line),
                ));
                let kind = if matches!(s.mutability, syn::StaticMutability::Mut(_)) {
                    ValueKind::StaticMut
                } else {
                    ValueKind::Static
                };
                out_constants.push(make_const(
                    kind,
                    &s.ident,
                    &s.ty,
                    Some(&s.expr),
                    &attrs,
                    visibility_of(&s.vis),
                    prefix,
                    impl_ctx,
                    (line, column, end_line),
                ));
            }
            syn::Item::Macro(m) => out_items.push(item_summary(
                ItemKind::Macro,
                m.mac
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
                &attrs,
                false,
                (line, column, end_line),
            )),
            syn::Item::Type(t) => out_items.push(item_summary(
                ItemKind::TypeAlias,
                t.ident.to_string(),
                &attrs,
                vis_is_public(&t.vis),
                (line, column, end_line),
            )),
            syn::Item::Use(_) => out_items.push(item_summary(
                ItemKind::Use,
                String::new(),
                &attrs,
                false,
                (line, column, end_line),
            )),
            syn::Item::ForeignMod(_) => out_items.push(item_summary(
                ItemKind::ForeignMod,
                String::new(),
                &attrs,
                false,
                (line, column, end_line),
            )),
            other => out_items.push(item_summary(
                ItemKind::Other,
                other
                    .to_token_stream()
                    .to_string()
                    .split_whitespace()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
                &attrs,
                false,
                (line, column, end_line),
            )),
        }
    }
}

fn item_attrs(item: &syn::Item) -> Vec<syn::Attribute> {
    use syn::Item;
    match item {
        Item::Const(i) => i.attrs.clone(),
        Item::Enum(i) => i.attrs.clone(),
        Item::ExternCrate(i) => i.attrs.clone(),
        Item::Fn(i) => i.attrs.clone(),
        Item::ForeignMod(i) => i.attrs.clone(),
        Item::Impl(i) => i.attrs.clone(),
        Item::Macro(i) => i.attrs.clone(),
        Item::Mod(i) => i.attrs.clone(),
        Item::Static(i) => i.attrs.clone(),
        Item::Struct(i) => i.attrs.clone(),
        Item::Trait(i) => i.attrs.clone(),
        Item::TraitAlias(i) => i.attrs.clone(),
        Item::Type(i) => i.attrs.clone(),
        Item::Union(i) => i.attrs.clone(),
        Item::Use(i) => i.attrs.clone(),
        _ => Vec::new(),
    }
}

fn item_summary(
    kind: ItemKind,
    name: String,
    attrs: &[syn::Attribute],
    is_public: bool,
    span: (usize, usize, usize),
) -> ItemSummary {
    ItemSummary {
        kind,
        name,
        line: span.0,
        column: span.1,
        end_line: span.2,
        is_public,
        trait_path: None,
        attributes: attribute_paths(attrs),
        doc: doc_comments(attrs),
        cfg_attrs: cfg_attr_tokens(attrs),
    }
}

/// Returns true when the attributes include `#[contracttype]` or
/// `#[contracterror]`, including fully qualified forms such as
/// `#[soroban_sdk::contracttype]`.
fn has_contract_type_attr(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        matches!(
            attribute_path(attr).rsplit("::").next(),
            Some("contracttype" | "contracterror")
        )
    })
}

fn contract_type_summary(
    name: String,
    kind: ContractTypeKind,
    attrs: &[syn::Attribute],
    is_public: bool,
    variants: Vec<String>,
    span: (usize, usize, usize),
) -> ContractTypeSummary {
    ContractTypeSummary {
        name,
        kind,
        is_public,
        attributes: attribute_paths(attrs),
        variants,
        line: span.0,
        column: span.1,
        end_line: span.2,
    }
}

/// Computes a best-effort logical module path for a source file.
pub fn module_path_for(path: &Path, crate_root: &Path) -> String {
    let rel = path.strip_prefix(crate_root).unwrap_or(path);
    let comps: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect();

    let start = comps.iter().position(|c| c == "src");
    let mut parts: Vec<String> = match start {
        Some(idx) => comps[idx + 1..].to_vec(),
        None => comps.clone(),
    };

    if let Some(last) = parts.last_mut() {
        let stem = Path::new(last.as_str())
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        *last = stem;
    }
    if parts.last().map(String::as_str) == Some("mod") {
        parts.pop();
    }
    if parts.last().map(String::as_str) == Some("lib")
        || parts.last().map(String::as_str) == Some("main")
    {
        parts.pop();
    }

    if parts.is_empty() {
        "crate".to_string()
    } else {
        format!("crate::{}", parts.join("::"))
    }
}

/// Maximum delimiter nesting depth accepted before parsing is skipped.
///
/// Recursive-descent parsers can overflow the stack on pathologically nested
/// input. Since scanned repositories are untrusted, we reject deeply nested
/// sources before handing them to the parser.
pub const MAX_NESTING_DEPTH: usize = 192;

fn skip_string(bytes: &[u8], mut i: usize) -> usize {
    let n = bytes.len();
    while i < n {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    n
}

fn skip_char_literal(bytes: &[u8], i: usize) -> usize {
    let n = bytes.len();
    if i >= n {
        return i;
    }
    if bytes[i] == b'\\' {
        let mut j = i + 1;
        if j < n && bytes[j] == b'u' {
            j += 1;
            if j < n && bytes[j] == b'{' {
                while j < n && bytes[j] != b'}' {
                    j += 1;
                }
                if j < n {
                    j += 1;
                }
            }
        } else {
            j += 1;
        }
        return if j < n && bytes[j] == b'\'' { j + 1 } else { j };
    }
    // `'x'` is a char literal; `'x` is a lifetime.
    if i + 1 < n && bytes[i + 1] == b'\'' {
        return i + 2;
    }
    i
}

/// Computes the maximum delimiter nesting depth, ignoring strings and comments.
pub fn max_delimiter_depth(src: &str) -> usize {
    let bytes = src.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut depth = 0usize;
    let mut max_depth = 0usize;

    while i < n {
        match bytes[i] {
            b'/' if i + 1 < n && bytes[i + 1] == b'/' => {
                i += 2;
                while i < n && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < n && bytes[i + 1] == b'*' => {
                i += 2;
                let mut level = 1usize;
                while i < n && level > 0 {
                    if i + 1 < n && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                        level += 1;
                        i += 2;
                    } else if i + 1 < n && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        level -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' => i = skip_string(bytes, i + 1),
            b'\'' => i = skip_char_literal(bytes, i + 1),
            b'r' | b'b' => {
                let mut j = i;
                if bytes[j] == b'b' {
                    j += 1;
                    if j >= n || bytes[j] != b'r' {
                        i += 1;
                        continue;
                    }
                }
                j += 1;
                let mut hashes = 0;
                while j < n && bytes[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                if j < n && bytes[j] == b'"' {
                    j += 1;
                    loop {
                        if j >= n {
                            break;
                        }
                        if bytes[j] == b'"' {
                            let mut k = j + 1;
                            let mut h = 0;
                            while h < hashes && k < n && bytes[k] == b'#' {
                                h += 1;
                                k += 1;
                            }
                            if h == hashes {
                                j = k;
                                break;
                            }
                        }
                        j += 1;
                    }
                    i = j;
                } else {
                    i += 1;
                }
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                max_depth = max_depth.max(depth);
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth = depth.saturating_sub(1);
                i += 1;
            }
            _ => i += 1,
        }
    }

    max_depth
}

#[derive(Default)]
struct MacroInventory {
    definitions: Vec<MacroDefinition>,
    invocations: Vec<MacroInvocation>,
}

impl MacroInventory {
    fn record_invocation(&mut self, mac: &syn::Macro) {
        let name = mac
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect::<Vec<_>>()
            .join("::");
        let (line, column) = span_start(mac);
        self.invocations.push(MacroInvocation {
            name,
            line,
            column,
            end_line: span_end_line(mac),
        });
    }
}

impl<'ast> Visit<'ast> for MacroInventory {
    fn visit_item_macro(&mut self, node: &'ast syn::ItemMacro) {
        if let Some(ident) = &node.ident {
            let (line, column) = span_start(node);
            self.definitions.push(MacroDefinition {
                name: ident.to_string(),
                line,
                column,
                end_line: span_end_line(node),
            });
            return;
        }
        self.record_invocation(&node.mac);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // A `macro_rules!` definition is handled by `visit_item_macro`; never
        // record it as a use. Macro bodies are opaque token streams, so no
        // expansion or resolution is attempted.
        if node
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "macro_rules")
        {
            return;
        }
        self.record_invocation(node);
    }
}

fn macro_inventory(file: &syn::File) -> (Vec<MacroDefinition>, Vec<MacroInvocation>) {
    let mut inventory = MacroInventory::default();
    inventory.visit_file(file);
    inventory.definitions.sort_by(|a, b| {
        (a.line, a.column, a.name.as_str()).cmp(&(b.line, b.column, b.name.as_str()))
    });
    inventory.invocations.sort_by(|a, b| {
        (a.line, a.column, a.name.as_str()).cmp(&(b.line, b.column, b.name.as_str()))
    });
    inventory.invocations.dedup();
    (inventory.definitions, inventory.invocations)
}

fn find_generated_marker(text: &str) -> Option<usize> {
    text.to_ascii_lowercase().find("@generated")
}

fn marker_position(
    text: &str,
    offset: usize,
    start_line: usize,
    start_column: usize,
) -> (usize, usize) {
    let before = &text[..offset];
    let newlines = before.matches('\n').count();
    if newlines == 0 {
        (start_line, start_column + before.chars().count())
    } else {
        let line = start_line + newlines;
        let column = before
            .rsplit('\n')
            .next()
            .map(|text| text.chars().count() + 1)
            .unwrap_or(1);
        (line, column)
    }
}

fn advance_position(
    bytes: &[u8],
    from: usize,
    to: usize,
    line: &mut usize,
    line_start: &mut usize,
) {
    let end = to.min(bytes.len());
    for (offset, byte) in bytes[from..end].iter().enumerate() {
        if *byte == b'\n' {
            *line += 1;
            *line_start = from + offset + 1;
        }
    }
}

fn raw_string_prefix(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut index = start;
    if bytes.get(index) == Some(&b'b') {
        if bytes.get(index + 1) == Some(&b'r') {
            index += 1;
        } else {
            return None;
        }
    }
    if bytes.get(index) != Some(&b'r') {
        return None;
    }
    index += 1;
    let mut hashes = 0usize;
    while bytes.get(index) == Some(&b'#') {
        hashes += 1;
        index += 1;
    }
    if bytes.get(index) == Some(&b'"') {
        Some((hashes, index + 1))
    } else {
        None
    }
}

fn raw_string_end(bytes: &[u8], from: usize, hashes: usize) -> Option<usize> {
    let n = bytes.len();
    let mut index = from;
    while index < n {
        if bytes[index] == b'"' {
            let mut offset = 0usize;
            while offset < hashes && bytes.get(index + 1 + offset) == Some(&b'#') {
                offset += 1;
            }
            if offset == hashes {
                return Some(index + 1 + hashes);
            }
        }
        index += 1;
    }
    None
}

fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_ident_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

/// Detects generated-code markers lexically.
///
/// `@generated` is recognized only inside comments and `include!` only as code
/// outside strings and comments. Detection never parses or expands the macro.
pub fn detect_generated_markers(source: &str) -> Vec<GeneratedMarker> {
    let bytes = source.as_bytes();
    let n = bytes.len();
    let mut markers = Vec::new();
    let mut index = 0usize;
    let mut line = 1usize;
    let mut line_start = 0usize;

    let column_at = |offset: usize, line_start: usize| {
        source
            .get(line_start..offset)
            .map(|text| text.chars().count() + 1)
            .unwrap_or(1)
    };

    while index < n {
        match bytes[index] {
            b'\n' => {
                line += 1;
                line_start = index + 1;
                index += 1;
            }
            b'/' if bytes.get(index + 1) == Some(&b'/') => {
                let start = index + 2;
                let mut end = start;
                while end < n && bytes[end] != b'\n' {
                    end += 1;
                }
                let text = &source[start..end];
                if let Some(offset) = find_generated_marker(text) {
                    let (marker_line, marker_column) =
                        marker_position(text, offset, line, column_at(start, line_start));
                    markers.push(GeneratedMarker {
                        kind: GeneratedMarkerKind::GeneratedComment,
                        line: marker_line,
                        column: marker_column,
                    });
                }
                index = end;
            }
            b'/' if bytes.get(index + 1) == Some(&b'*') => {
                let start = index + 2;
                let start_line = line;
                let start_column = column_at(start, line_start);
                let mut end = start;
                let mut depth = 1usize;
                while end < n && depth > 0 {
                    if bytes.get(end) == Some(&b'/') && bytes.get(end + 1) == Some(&b'*') {
                        depth += 1;
                        end += 2;
                    } else if bytes.get(end) == Some(&b'*') && bytes.get(end + 1) == Some(&b'/') {
                        depth -= 1;
                        end += 2;
                    } else {
                        end += 1;
                    }
                }
                let content_end = if depth == 0 { end.saturating_sub(2) } else { n };
                let text = &source[start..content_end];
                if let Some(offset) = find_generated_marker(text) {
                    let (marker_line, marker_column) =
                        marker_position(text, offset, start_line, start_column);
                    markers.push(GeneratedMarker {
                        kind: GeneratedMarkerKind::GeneratedComment,
                        line: marker_line,
                        column: marker_column,
                    });
                }
                advance_position(bytes, index, end, &mut line, &mut line_start);
                index = end;
            }
            b'"' => {
                let end = skip_string(bytes, index + 1);
                advance_position(bytes, index, end, &mut line, &mut line_start);
                index = end;
            }
            b'\'' => {
                let end = skip_char_literal(bytes, index + 1);
                advance_position(bytes, index, end, &mut line, &mut line_start);
                index = end;
            }
            b'r' | b'b' => {
                if let Some((hashes, content_start)) = raw_string_prefix(bytes, index) {
                    let end = raw_string_end(bytes, content_start, hashes).unwrap_or(n);
                    advance_position(bytes, index, end, &mut line, &mut line_start);
                    index = end;
                } else {
                    let start = index;
                    let mut end = index + 1;
                    while end < n && is_ident_continue(bytes[end]) {
                        end += 1;
                    }
                    if &source[start..end] == "include" {
                        let mut after = end;
                        while after < n && bytes[after].is_ascii_whitespace() {
                            after += 1;
                        }
                        if bytes.get(after) == Some(&b'!') {
                            markers.push(GeneratedMarker {
                                kind: GeneratedMarkerKind::IncludeMacro,
                                line,
                                column: column_at(start, line_start),
                            });
                        }
                    }
                    index = end;
                }
            }
            byte if is_ident_start(byte) => {
                let start = index;
                let mut end = index + 1;
                while end < n && is_ident_continue(bytes[end]) {
                    end += 1;
                }
                if &source[start..end] == "include" {
                    let mut after = end;
                    while after < n && bytes[after].is_ascii_whitespace() {
                        after += 1;
                    }
                    if bytes.get(after) == Some(&b'!') {
                        markers.push(GeneratedMarker {
                            kind: GeneratedMarkerKind::IncludeMacro,
                            line,
                            column: column_at(start, line_start),
                        });
                    }
                }
                index = end;
            }
            _ => index += 1,
        }
    }

    markers.sort_by(|a, b| {
        (a.line, a.column, a.kind.as_str()).cmp(&(b.line, b.column, b.kind.as_str()))
    });
    markers.dedup();
    markers
}

/// Normalizes a source document for parsing only.
///
/// A leading UTF-8 BOM is removed and CRLF/CR line endings become LF so line
/// and column spans match the visible source. The file on disk is never
/// modified; the returned value is borrowed when no normalization is needed.
fn normalize_source_text(content: &str) -> Cow<'_, str> {
    let without_bom = content.strip_prefix('\u{feff}').unwrap_or(content);
    if without_bom.contains('\r') {
        return Cow::Owned(without_bom.replace("\r\n", "\n").replace('\r', "\n"));
    }
    if without_bom.len() == content.len() {
        Cow::Borrowed(content)
    } else {
        Cow::Borrowed(without_bom)
    }
}

/// Parses a single source file's content.
///
/// The content is normalized in memory (BOM stripped, CRLF/CR to LF) before
/// parsing so spans are accurate; the source file is never written back.
pub fn parse_source(path: &Path, crate_root: &Path, content: &str) -> ParsedSource {
    parse_source_with_options(path, crate_root, content, false)
}

/// Parses a single source file's content with discovery options.
///
/// When `exclude_tests` is set, items gated behind `#[cfg(test)]` are removed
/// before analysis so detectors never see test-only code.
pub fn parse_source_with_options(
    path: &Path,
    crate_root: &Path,
    content: &str,
    exclude_tests: bool,
) -> ParsedSource {
    let normalized = normalize_source_text(content);
    let content = normalized.as_ref();
    let module_path = module_path_for(path, crate_root);
    let generated_markers = detect_generated_markers(content);

    if max_delimiter_depth(content) > MAX_NESTING_DEPTH {
        return ParsedSource {
            path: path.to_path_buf(),
            module_path,
            syntax: None,
            parse_error: Some(format!(
                "source nesting exceeds the {MAX_NESTING_DEPTH}-level safety limit"
            )),
            items: Vec::new(),
            functions: Vec::new(),
            constants: Vec::new(),
            macro_definitions: Vec::new(),
            macro_invocations: Vec::new(),
            generated_markers,
            contract_types: Vec::new(),
            contract_definitions: Vec::new(),
            suppressions: Vec::new(),
            imports: crate::imports::ImportMap::default(),
        };
    }

    match syn::parse_file(content) {
        Ok(mut file) => {
            if exclude_tests {
                prune_cfg_test_items(&mut file.items);
            }
            let mut items = Vec::new();
            let mut functions = Vec::new();
            let mut constants = Vec::new();
            let mut contract_types = Vec::new();
            let mut contract_definitions = Vec::new();
            walk_items(
                &file.items,
                "",
                None,
                path,
                &mut items,
                &mut functions,
                &mut constants,
                &mut contract_types,
                &mut contract_definitions,
            );
            let (macro_definitions, macro_invocations) = macro_inventory(&file);
            let suppressions = crate::suppression::detect(content, path, &item_spans(&file));
            let imports = crate::imports::ImportMap::from_file(&file);
            ParsedSource {
                path: path.to_path_buf(),
                module_path,
                syntax: Some(file),
                parse_error: None,
                items,
                functions,
                constants,
                macro_definitions,
                macro_invocations,
                generated_markers,
                contract_types,
                contract_definitions,
                suppressions,
                imports,
            }
        }
        Err(err) => ParsedSource {
            path: path.to_path_buf(),
            module_path,
            syntax: None,
            parse_error: Some(err.to_string()),
            items: Vec::new(),
            functions: Vec::new(),
            constants: Vec::new(),
            macro_definitions: Vec::new(),
            macro_invocations: Vec::new(),
            generated_markers,
            contract_types: Vec::new(),
            contract_definitions: Vec::new(),
            suppressions: Vec::new(),
            imports: crate::imports::ImportMap::default(),
        },
    }
}

/// Returns true if any attribute is a positive `cfg(test)` gate.
///
/// `cfg(not(test))` is deliberately treated as non-test code, and
/// `cfg(feature = "test")` is not the built-in `test` cfg and is ignored.
fn attrs_gated_by_test(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|attr| attribute_path(attr) == "cfg" && cfg_meta_mentions_test(&attr.meta))
}

fn cfg_meta_mentions_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) => {
            let name = list
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            if name == "not" {
                return false;
            }
            list.parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .map(|metas| metas.iter().any(cfg_meta_mentions_test))
            .unwrap_or(false)
        }
        syn::Meta::NameValue(_) => false,
    }
}

fn item_attrs_slice(item: &syn::Item) -> &[syn::Attribute] {
    use syn::Item;
    match item {
        Item::Const(i) => &i.attrs,
        Item::Enum(i) => &i.attrs,
        Item::ExternCrate(i) => &i.attrs,
        Item::Fn(i) => &i.attrs,
        Item::ForeignMod(i) => &i.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Macro(i) => &i.attrs,
        Item::Mod(i) => &i.attrs,
        Item::Static(i) => &i.attrs,
        Item::Struct(i) => &i.attrs,
        Item::Trait(i) => &i.attrs,
        Item::TraitAlias(i) => &i.attrs,
        Item::Type(i) => &i.attrs,
        Item::Union(i) => &i.attrs,
        Item::Use(i) => &i.attrs,
        _ => &[],
    }
}

/// Removes items gated behind `#[cfg(test)]`, recursing into modules and impls.
fn prune_cfg_test_items(items: &mut Vec<syn::Item>) {
    items.retain(|item| !attrs_gated_by_test(item_attrs_slice(item)));
    for item in items.iter_mut() {
        match item {
            syn::Item::Mod(module) => {
                if let Some((_, sub_items)) = &mut module.content {
                    prune_cfg_test_items(sub_items);
                }
            }
            syn::Item::Impl(imp) => imp.items.retain(|impl_item| match impl_item {
                syn::ImplItem::Fn(function) => !attrs_gated_by_test(&function.attrs),
                _ => true,
            }),
            syn::Item::Trait(tr) => tr.items.retain(|trait_item| match trait_item {
                syn::TraitItem::Fn(function) => !attrs_gated_by_test(&function.attrs),
                _ => true,
            }),
            _ => {}
        }
    }
}

/// Returns the `(first_line, last_line)` bounds of every item in a file.
///
/// Used to widen an inline suppression directive to the item it is anchored to.
/// Spans are taken from the syntax tree so they cover the whole item, including
/// the body of a function and the attributes above it.
fn item_spans(file: &syn::File) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    collect_item_spans(&file.items, &mut spans);
    spans.sort_unstable();
    spans.dedup();
    spans
}

/// Collects item spans, descending into modules, `impl` blocks, and traits.
fn collect_item_spans(items: &[syn::Item], out: &mut Vec<(usize, usize)>) {
    for item in items {
        out.push((span_start(item).0, span_end_line(item)));
        match item {
            syn::Item::Impl(imp) => {
                for impl_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = impl_item {
                        out.push((span_start(f).0, span_end_line(f)));
                    }
                }
            }
            syn::Item::Trait(tr) => {
                for trait_item in &tr.items {
                    if let syn::TraitItem::Fn(f) = trait_item {
                        out.push((span_start(f).0, span_end_line(f)));
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, sub_items)) = &m.content {
                    collect_item_spans(sub_items, out);
                }
            }
            _ => {}
        }
    }
}

/// A manifest directory that may act as a crate root.
#[derive(Debug, Clone)]
struct CrateRootCandidate {
    /// Directory containing the manifest.
    dir: PathBuf,
    /// Whether the manifest is a member of its enclosing workspace.
    ///
    /// A standalone package (no enclosing workspace) is always a member of its
    /// own one-package universe. A package nested inside a workspace is only a
    /// crate root when its directory matches one of that workspace's `members`
    /// globs; otherwise Cargo does not consider it part of the workspace.
    is_member: bool,
}

/// Builds crate-root candidates and verifies workspace membership (#47).
///
/// Nested packages that are not matched by an enclosing workspace's `members`
/// globs must not win the "nearest manifest" race. Treating them as crate roots
/// produces module paths for files the workspace does not actually include.
fn crate_root_candidates(manifests: &[crate::model::Manifest]) -> Vec<CrateRootCandidate> {
    use globset::GlobBuilder;

    // Enclosing workspaces, keyed by directory. Invalid member globs are
    // ignored: they cannot prove membership, so the package fails closed and is
    // reported as ambiguous rather than silently accepted.
    let workspaces: Vec<(PathBuf, Vec<globset::GlobMatcher>)> = manifests
        .iter()
        .filter_map(|manifest| {
            let workspace = manifest.workspace.as_ref()?;
            let dir = manifest.path.parent()?.to_path_buf();
            let globs = workspace
                .members
                .iter()
                .filter_map(|pattern| {
                    GlobBuilder::new(pattern)
                        .literal_separator(true)
                        .build()
                        .ok()
                        .map(|glob| glob.compile_matcher())
                })
                .collect();
            Some((dir, globs))
        })
        .collect();

    manifests
        .iter()
        .filter_map(|manifest| {
            // A `[workspace]`-only manifest is not a package and therefore not
            // a crate root. The scan root remains the fallback for files that
            // only sit under a virtual workspace.
            manifest.package.as_ref()?;
            let dir = manifest.path.parent()?.to_path_buf();

            let enclosing = workspaces
                .iter()
                .filter(|(workspace_dir, _)| {
                    dir != *workspace_dir && dir.starts_with(workspace_dir)
                })
                .max_by_key(|(workspace_dir, _)| workspace_dir.components().count());

            let is_member = match enclosing {
                None => true,
                Some((workspace_dir, globs)) => {
                    let relative = dir.strip_prefix(workspace_dir).unwrap_or(&dir);
                    let relative = relative.to_string_lossy().replace('\\', "/");
                    globs.iter().any(|glob| {
                        glob.is_match(&relative) || glob.is_match(format!("{relative}/Cargo.toml"))
                    })
                }
            };

            Some(CrateRootCandidate { dir, is_member })
        })
        .collect()
}

/// Chooses the crate root for `path`, or reports why the choice is ambiguous.
fn associate_crate_root(
    path: &Path,
    candidates: &[CrateRootCandidate],
    root: &Path,
) -> (PathBuf, Option<String>) {
    let mut matching: Vec<&CrateRootCandidate> = candidates
        .iter()
        .filter(|candidate| path.starts_with(&candidate.dir))
        .collect();
    matching.sort_by_key(|candidate| candidate.dir.components().count());

    let chosen = matching
        .iter()
        .filter(|candidate| candidate.is_member)
        .max_by_key(|candidate| candidate.dir.components().count())
        .copied();
    let deepest = matching.last().copied();

    match chosen {
        Some(candidate) => {
            let ambiguous = deepest.is_some_and(|deepest| {
                deepest.dir.components().count() > candidate.dir.components().count()
            });
            let message = ambiguous.then(|| {
                format!(
                    "ambiguous crate root: a nested manifest is not a workspace member; \
                     using {}",
                    candidate.dir.display()
                )
            });
            (candidate.dir.clone(), message)
        }
        None => {
            let message = deepest.map(|candidate| {
                format!(
                    "ambiguous crate root: the nearest manifest is not a workspace member; \
                     using the scan root instead of {}",
                    candidate.dir.display()
                )
            });
            (root.to_path_buf(), message)
        }
    }
}

/// One external `mod name;` declaration found in a parsed file.
struct ModuleDeclaration {
    name: String,
    prefix: String,
    path_attr: Option<String>,
}

/// Resolves file module paths by following `mod` declarations from crate roots.
///
/// Standard `foo.rs`/`foo/mod.rs` resolution and `#[path = "..."]` are honored.
/// A `#[path]` target that escapes the crate root is rejected and reported as
/// `SOURCE-003`; the file keeps its best-effort file-based module path.
fn resolve_module_paths(
    sources: &mut [ParsedSource],
    manifests: &[crate::model::Manifest],
    root: &Path,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let candidates = crate_root_candidates(manifests);
    let index: BTreeMap<PathBuf, usize> = sources
        .iter()
        .enumerate()
        .map(|(idx, source)| (path_key(&source.path), idx))
        .collect();

    let mut visited = vec![false; sources.len()];
    let mut queue = VecDeque::new();
    for (idx, source) in sources.iter_mut().enumerate() {
        let (crate_root, _) = associate_crate_root(&source.path, &candidates, root);
        if is_crate_root_file(&source.path, &crate_root) {
            source.module_path = "crate".to_string();
            visited[idx] = true;
            queue.push_back(idx);
        }
    }

    while let Some(idx) = queue.pop_front() {
        let (crate_root, _) = associate_crate_root(&sources[idx].path, &candidates, root);
        let declarations = sources[idx]
            .syntax
            .as_ref()
            .map(|syntax| {
                let mut declarations = Vec::new();
                collect_module_declarations(&syntax.items, "", &mut declarations);
                declarations
            })
            .unwrap_or_default();
        let parent_path = sources[idx].path.clone();
        let parent_module = sources[idx].module_path.clone();

        for declaration in declarations {
            let Some(child_path) =
                resolve_declared_module(&parent_path, &crate_root, &declaration, diagnostics)
            else {
                continue;
            };
            let Some(&child_idx) = index.get(&path_key(&child_path)) else {
                continue;
            };
            if visited[child_idx] {
                continue;
            }
            visited[child_idx] = true;
            let prefix = if declaration.prefix.is_empty() {
                parent_module.clone()
            } else {
                format!("{parent_module}::{}", declaration.prefix)
            };
            sources[child_idx].module_path = format!("{prefix}::{}", declaration.name);
            queue.push_back(child_idx);
        }
    }
}

fn path_key(path: &Path) -> PathBuf {
    path.components().collect()
}

fn is_crate_root_file(path: &Path, crate_root: &Path) -> bool {
    path == crate_root.join("src").join("lib.rs") || path == crate_root.join("src").join("main.rs")
}

fn collect_module_declarations(
    items: &[syn::Item],
    prefix: &str,
    out: &mut Vec<ModuleDeclaration>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let name = module.ident.to_string();
        let nested_prefix = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}::{name}")
        };
        match &module.content {
            Some((_, items)) => collect_module_declarations(items, &nested_prefix, out),
            None => out.push(ModuleDeclaration {
                name,
                prefix: prefix.to_string(),
                path_attr: module.attrs.iter().find_map(path_attribute),
            }),
        }
    }
}

fn path_attribute(attribute: &syn::Attribute) -> Option<String> {
    if !attribute.path().is_ident("path") {
        return None;
    }
    let syn::Meta::NameValue(name_value) = &attribute.meta else {
        return None;
    };
    let syn::Expr::Lit(literal) = &name_value.value else {
        return None;
    };
    let syn::Lit::Str(value) = &literal.lit else {
        return None;
    };
    Some(value.value())
}

fn resolve_declared_module(
    parent_file: &Path,
    crate_root: &Path,
    declaration: &ModuleDeclaration,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<PathBuf> {
    if let Some(raw) = &declaration.path_attr {
        let base = parent_file.parent()?;
        let candidate = normalize_lexical(&base.join(raw))?;
        if !candidate.starts_with(crate_root) {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::SourceModulePathRejected,
                format!(
                    "rejected #[path = {raw:?}] for module {:?}: it escapes the crate root",
                    declaration.name
                ),
                Some(parent_file.to_path_buf()),
            ));
            return None;
        }
        return candidate.is_file().then_some(candidate);
    }

    let module_dir = module_directory(parent_file, crate_root)?;
    let flat = module_dir.join(format!("{}.rs", declaration.name));
    if flat.is_file() {
        return Some(flat);
    }
    let nested = module_dir.join(&declaration.name).join("mod.rs");
    nested.is_file().then_some(nested)
}

fn module_directory(path: &Path, crate_root: &Path) -> Option<PathBuf> {
    let parent = path.parent()?.to_path_buf();
    let is_mod_rs = path.file_name().is_some_and(|name| name == "mod.rs");
    if is_mod_rs || is_crate_root_file(path, crate_root) {
        return Some(parent);
    }
    let stem = path.file_stem()?.to_string_lossy();
    Some(parent.join(stem.as_ref()))
}

fn normalize_lexical(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return None;
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Some(normalized)
}

/// Options controlling source loading and generated-code handling.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceOptions {
    /// Skip items gated behind `#[cfg(test)]`.
    pub exclude_tests: bool,
    /// Exclude files with generated-code markers instead of marking them.
    pub exclude_generated: bool,
}

/// Parsed sources plus load-time diagnostics and generated-file counts.
pub struct LoadedSources {
    /// Parsed source files.
    pub sources: Vec<ParsedSource>,
    /// Diagnostics produced while loading.
    pub diagnostics: Vec<Diagnostic>,
    /// Generated files excluded before analysis.
    pub generated_files_excluded: usize,
}

/// Loads and parses a set of Rust source files.
///
/// Unreadable or oversized files produce diagnostics and are skipped. Every
/// other file is parsed; parse failures are recorded on the [`ParsedSource`].
pub fn load_sources(
    files: &[PathBuf],
    manifests: &[crate::model::Manifest],
    root: &Path,
    exclude_tests: bool,
) -> (Vec<ParsedSource>, Vec<Diagnostic>) {
    let loaded = load_sources_with_options(
        files,
        manifests,
        root,
        SourceOptions {
            exclude_tests,
            exclude_generated: false,
        },
    );
    (loaded.sources, loaded.diagnostics)
}

/// Loads sources with generated-code marking or exclusion.
pub fn load_sources_with_options(
    files: &[PathBuf],
    manifests: &[crate::model::Manifest],
    root: &Path,
    options: SourceOptions,
) -> LoadedSources {
    let candidates = crate_root_candidates(manifests);

    let mut sources = Vec::new();
    let mut diagnostics = Vec::new();
    let mut generated_files_excluded = 0usize;

    for path in files {
        match std::fs::metadata(path) {
            Ok(meta) if meta.len() > MAX_SOURCE_BYTES => {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::SourceTooLarge,
                    format!(
                        "skipping source file larger than {} bytes",
                        MAX_SOURCE_BYTES
                    ),
                    Some(path.clone()),
                ));
                continue;
            }
            Ok(_) => {}
            Err(err) => {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::SourceUnreadable,
                    format!("skipping unreadable source file: {err}"),
                    Some(path.clone()),
                ));
                continue;
            }
        }

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(err) => {
                diagnostics.push(Diagnostic::warning(
                    DiagnosticCode::SourceUnreadable,
                    format!("skipping unreadable source file: {err}"),
                    Some(path.clone()),
                ));
                continue;
            }
        };

        let (crate_root, ambiguity) = associate_crate_root(path, &candidates, root);
        if let Some(message) = ambiguity {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::AmbiguousCrateRoot,
                message,
                Some(path.clone()),
            ));
        }
        let source = parse_source_with_options(path, &crate_root, &content, options.exclude_tests);
        if let Some(err) = &source.parse_error {
            diagnostics.push(Diagnostic::warning(
                DiagnosticCode::ParseFailed,
                format!("failed to parse source: {err}"),
                Some(path.clone()),
            ));
        }

        if source.is_generated() {
            if options.exclude_generated {
                generated_files_excluded += 1;
                diagnostics.push(Diagnostic::info(
                    DiagnosticCode::GeneratedFileExcluded,
                    format!(
                        "excluding generated source file ({} marker(s); exclude_generated is enabled)",
                        source.generated_markers.len()
                    ),
                    Some(path.clone()),
                ));
                continue;
            }
            diagnostics.push(Diagnostic::info(
                DiagnosticCode::GeneratedFileMarked,
                format!(
                    "source file is marked as generated ({} marker(s)); findings are still reported",
                    source.generated_markers.len()
                ),
                Some(path.clone()),
            ));
        }

        if !source.macro_invocations.is_empty() {
            let mut names: Vec<&str> = source
                .macro_invocations
                .iter()
                .map(|invocation| invocation.name.as_str())
                .collect();
            names.sort_unstable();
            names.dedup();
            let shown = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
            let suffix = if names.len() > 5 {
                format!(" (+{} more)", names.len() - 5)
            } else {
                String::new()
            };
            diagnostics.push(Diagnostic::info(
                DiagnosticCode::UnexpandedMacro,
                format!(
                    "{} macro invocation(s) were not expanded: {shown}{suffix}",
                    source.macro_invocations.len()
                ),
                Some(path.clone()),
            ));
        }

        sources.push(source);
    }

    resolve_module_paths(&mut sources, manifests, root, &mut diagnostics);

    LoadedSources {
        sources,
        diagnostics,
        generated_files_excluded,
    }
}

/// Applies contract-definition evidence from parsed sources to a project.
pub fn apply_source_evidence(project: &mut Project, sources: &[ParsedSource]) {
    for source in sources {
        for location in &source.contract_definitions {
            soroban::note_contract_definition(&mut project.soroban, location);
        }
    }
    project.kind = soroban::classify(&project.soroban);
}

/// Convenience wrapper returning updated [`SorobanInfo`] for tests.
pub fn soroban_evidence(sources: &[ParsedSource]) -> SorobanInfo {
    let mut info = SorobanInfo::default();
    for source in sources {
        for location in &source.contract_definitions {
            soroban::note_contract_definition(&mut info, location);
        }
    }
    info
}

/// Reads and parses a single file from disk (test/helper convenience).
pub fn parse_file(path: &Path, crate_root: &Path) -> Result<ParsedSource, ScanError> {
    let content = std::fs::read_to_string(path).map_err(|e| ScanError::io(path, e))?;
    Ok(parse_source(path, crate_root, &content))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> ParsedSource {
        parse_source(Path::new("src/lib.rs"), Path::new("."), src)
    }

    fn temp_project(name: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!(
            "soroban-scan-modules-{}-{}",
            name,
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    fn load_module_paths(
        root: &Path,
        files: &[PathBuf],
    ) -> (Vec<(String, String)>, Vec<Diagnostic>) {
        write(
            &root.join("Cargo.toml"),
            "[package]\nname = \"module-fixture\"\nversion = \"0.1.0\"\n",
        );
        let manifest = crate::manifest::parse_manifest(
            &root.join("Cargo.toml"),
            "[package]\nname = \"module-fixture\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        let loaded = load_sources_with_options(files, &[manifest], root, SourceOptions::default());
        let paths = loaded
            .sources
            .iter()
            .map(|source| {
                (
                    source
                        .path
                        .strip_prefix(root)
                        .unwrap_or(&source.path)
                        .to_string_lossy()
                        .replace('\\', "/"),
                    source.module_path.clone(),
                )
            })
            .collect();
        (paths, loaded.diagnostics)
    }

    #[test]
    fn module_paths_follow_mod_declarations_and_mod_rs() {
        let root = temp_project("mod-rs");
        let lib = root.join("src/lib.rs");
        let foo = root.join("src/foo.rs");
        let bar = root.join("src/foo/bar.rs");
        let baz_mod = root.join("src/foo/baz/mod.rs");
        let baz_qux = root.join("src/foo/baz/qux.rs");
        write(&lib, "mod foo;\n");
        write(&foo, "mod bar;\nmod baz;\n");
        write(&bar, "pub fn bar() {}\n");
        write(&baz_mod, "mod qux;\n");
        write(&baz_qux, "pub fn qux() {}\n");

        let (paths, diagnostics) = load_module_paths(&root, &[lib, foo, bar, baz_mod, baz_qux]);

        let by_file: std::collections::BTreeMap<_, _> = paths.into_iter().collect();
        assert_eq!(by_file["src/lib.rs"], "crate");
        assert_eq!(by_file["src/foo.rs"], "crate::foo");
        assert_eq!(by_file["src/foo/bar.rs"], "crate::foo::bar");
        assert_eq!(by_file["src/foo/baz/mod.rs"], "crate::foo::baz");
        assert_eq!(by_file["src/foo/baz/qux.rs"], "crate::foo::baz::qux");
        assert!(!diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::SourceModulePathRejected));
    }

    #[test]
    fn module_paths_honor_path_attributes() {
        let root = temp_project("path-attr");
        let lib = root.join("src/lib.rs");
        let custom = root.join("src/alt/custom.rs");
        write(&lib, "#[path = \"alt/custom.rs\"]\nmod custom;\n");
        write(&custom, "pub fn custom() {}\n");

        let (paths, diagnostics) = load_module_paths(&root, &[lib, custom]);

        let by_file: std::collections::BTreeMap<_, _> = paths.into_iter().collect();
        assert_eq!(by_file["src/alt/custom.rs"], "crate::custom");
        assert!(!diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::SourceModulePathRejected));
    }

    #[test]
    fn path_attributes_escaping_the_crate_root_are_rejected() {
        let root = temp_project("path-escape");
        let lib = root.join("src/lib.rs");
        let outside = root.join("outside.rs");
        write(&lib, "#[path = \"../../outside.rs\"]\nmod escape;\n");
        write(&outside, "pub fn outside() {}\n");

        let (paths, diagnostics) = load_module_paths(&root, &[lib, outside]);

        let by_file: std::collections::BTreeMap<_, _> = paths.into_iter().collect();
        assert_eq!(by_file["src/lib.rs"], "crate");
        // The escaped file is not attached to the declared module name.
        assert_eq!(by_file["outside.rs"], "crate::outside");
        assert!(diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == DiagnosticCode::SourceModulePathRejected));
    }

    #[test]
    fn captures_function_spans() {
        let s = parse("fn a() {}\n\nfn b() {}\n");
        assert!(s.is_parsed());
        assert_eq!(s.functions.len(), 2);
        assert_eq!(s.functions[0].name, "a");
        assert_eq!(s.functions[0].line, 1);
        assert_eq!(s.functions[1].name, "b");
        assert_eq!(s.functions[1].line, 3);
    }

    #[test]
    fn captures_multiline_doc_comments_on_functions() {
        let s = parse(
            "/// Permissionless: no auth required.\n\
             ///\n\
             /// Called by the settlement worker.\n\
             pub fn settle() {}\n",
        );
        assert_eq!(s.functions.len(), 1);
        assert_eq!(
            s.functions[0].doc,
            "Permissionless: no auth required.\n\nCalled by the settlement worker."
        );
    }

    #[test]
    fn captures_doc_comments_on_non_function_items() {
        let s = parse(
            "/// Stored settlement record.\n\
             ///\n\
             /// Kept stable for migrations.\n\
             pub struct Settlement {\n    pub amount: i128,\n}\n",
        );
        let item = s
            .items
            .iter()
            .find(|item| item.name == "Settlement")
            .expect("struct item");
        assert_eq!(
            item.doc,
            "Stored settlement record.\n\nKept stable for migrations."
        );
    }

    #[test]
    fn captures_explicit_doc_attribute_forms() {
        let s = parse("#[doc = \"Explicit first line\"]\n#[doc = \"Explicit second line\"]\nfn documented() {}\n");
        assert_eq!(
            s.functions[0].doc,
            "Explicit first line\nExplicit second line"
        );
    }

    #[test]
    fn undocumented_items_have_empty_doc() {
        let s = parse("fn plain() {}\n");
        assert_eq!(s.functions[0].doc, "");
    }

    #[test]
    fn file_level_inner_comments_stay_on_the_file_and_not_on_items() {
        // `//!` and `/*! ... */` at the top of a file are inner attributes of
        // the file, not of the item that follows them, so `syn` keeps them in
        // `File::attrs`.
        for src in [
            "//! Module doc.\npub fn f() {}\n",
            "/*! Module doc. */\npub fn f() {}\n",
        ] {
            let s = parse(src);
            assert!(s.is_parsed(), "parse error: {:?}", s.parse_error);
            assert_eq!(s.functions.len(), 1);
            assert_eq!(s.functions[0].doc, "");

            let syntax = s.syntax.as_ref().expect("parsed syntax tree");
            assert!(
                syntax.attrs.iter().any(|attr| {
                    attr.path().is_ident("doc") && matches!(&attr.meta, syn::Meta::NameValue(_))
                }),
                "file-level doc attribute is expected on the file: {:?}",
                syntax.attrs
            );
        }
    }

    #[test]
    fn inner_comments_inside_a_module_are_reported_on_the_module() {
        // `//!` inside a `mod` body is an inner attribute of that module, so
        // `syn` attaches it to the module item and it is inventoried there.
        let s = parse(
            "pub mod inner {\n\
             //! Inner module doc.\n\
             pub fn g() {}\n\
             }\n",
        );
        assert!(s.is_parsed(), "parse error: {:?}", s.parse_error);
        let module = s
            .items
            .iter()
            .find(|item| item.name == "inner")
            .expect("module item");
        assert_eq!(module.kind, ItemKind::Module);
        assert_eq!(module.doc, "Inner module doc.");
    }

    #[test]
    fn block_doc_comments_keep_their_gutter_verbatim() {
        // Only one leading space is removed per line, so the `*` gutter of a
        // block comment survives into the joined text.
        let s = parse("/**\n * Block doc line.\n */\npub fn f() {}\n");
        assert_eq!(s.functions[0].doc, "* Block doc line.");

        let single_line = parse("/** Block doc line. */\npub fn g() {}\n");
        assert_eq!(single_line.functions[0].doc, "Block doc line.");
    }

    #[test]
    fn strips_bom_and_normalizes_crlf_without_shifting_lines() {
        let s = parse("\u{feff}fn a() {}\r\n\r\nfn b() {}\r\n");
        assert!(s.is_parsed(), "parse error: {:?}", s.parse_error);
        assert_eq!(s.functions.len(), 2);
        assert_eq!(s.functions[0].name, "a");
        assert_eq!((s.functions[0].line, s.functions[0].column), (1, 1));
        assert_eq!(s.functions[1].name, "b");
        assert_eq!((s.functions[1].line, s.functions[1].column), (3, 1));
    }

    #[test]
    fn normalizes_lone_carriage_returns_for_spans() {
        let s = parse("fn a() {}\rfn b() {}\r");
        assert!(s.is_parsed(), "parse error: {:?}", s.parse_error);
        assert_eq!(s.functions.len(), 2);
        assert_eq!(s.functions[1].line, 2);
        assert_eq!(s.functions[1].column, 1);
    }

    #[test]
    fn bom_and_crlf_do_not_change_reported_end_lines() {
        let lf = parse("fn a() {\n    let x = 1;\n}\n");
        let crlf = parse("\u{feff}fn a() {\r\n    let x = 1;\r\n}\r\n");
        assert_eq!(lf.functions[0].end_line, crlf.functions[0].end_line);
        assert_eq!(lf.functions[0].line, crlf.functions[0].line);
        assert_eq!(lf.functions[0].column, crlf.functions[0].column);
    }

    #[test]
    fn suppressions_cover_whole_function_items() {
        let src = concat!(
            "struct Vault;\n",
            "impl Vault {\n",
            "    // soroban-scan: ignore SS-001 -- reviewed\n",
            "    pub fn f(&self) {\n",
            "        let x = 1;\n",
            "    }\n",
            "}\n",
        );
        let s = parse(src);
        assert_eq!(s.suppressions.len(), 1);
        let suppression = &s.suppressions[0];
        assert_eq!(suppression.line, 3);
        assert_eq!((suppression.start_line, suppression.end_line), (4, 6));
        assert!(suppression.applies_to("src/lib.rs", 5, "SS-001"));
        assert!(!suppression.applies_to("src/lib.rs", 7, "SS-001"));
        assert!(!suppression.applies_to("src/lib.rs", 5, "SS-002"));
    }

    #[test]
    fn identifies_contract_entry_points() {
        let src = r#"
use soroban_sdk::{contract, contractimpl, Env};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn transfer(env: Env, amount: i128) {}
}
"#;
        let s = parse(src);
        assert_eq!(s.contract_definitions.len(), 2);
        assert!(s.contract_definitions[0].contains("src/lib.rs:"));
        let entry: Vec<_> = s.contract_entry_points().collect();
        assert_eq!(entry.len(), 1);
        assert_eq!(entry[0].name, "transfer");
        assert_eq!(entry[0].params.len(), 2);
        assert_eq!(entry[0].params[1].name, "amount");
        assert_eq!(entry[0].in_impl.as_deref(), Some("C"));
    }

    #[test]
    fn records_trait_paths_on_impls_and_functions() {
        let src = r#"
trait Token {
    fn transfer(&self);
}

struct Vault;

impl Vault {
    fn inherent(&self) {}
}

impl Token for Vault {
    fn transfer(&self) {}
}
"#;
        let s = parse(src);

        let inherent = s.functions.iter().find(|f| f.name == "inherent").unwrap();
        assert_eq!(inherent.in_impl.as_deref(), Some("Vault"));
        assert_eq!(inherent.trait_path, None);

        let transfer = s
            .functions
            .iter()
            .find(|f| f.name == "transfer" && f.in_impl.as_deref() == Some("Vault"))
            .unwrap();
        assert_eq!(transfer.trait_path.as_deref(), Some("Token"));

        let trait_method = s
            .functions
            .iter()
            .find(|f| f.name == "transfer" && f.in_impl.as_deref() == Some("Token"))
            .unwrap();
        assert_eq!(trait_method.trait_path, None);

        let trait_impl = s
            .items
            .iter()
            .find(|item| item.kind == ItemKind::Impl && item.trait_path.is_some())
            .unwrap();
        assert_eq!(trait_impl.trait_path.as_deref(), Some("Token"));
        assert_eq!(
            s.items
                .iter()
                .filter(|item| item.kind == ItemKind::Impl)
                .count(),
            2
        );

        // Trait definitions are not implementations.
        let trait_item = s
            .items
            .iter()
            .find(|item| item.kind == ItemKind::Trait)
            .unwrap();
        assert_eq!(trait_item.trait_path, None);
    }

    #[test]
    fn records_qualified_trait_paths() {
        let src = r#"
mod token {
    pub trait Token {}
}

struct Vault;

impl token::Token for Vault {
    fn transfer(&self) {}
}
"#;
        let s = parse(src);
        let transfer = s.functions.iter().find(|f| f.name == "transfer").unwrap();
        assert_eq!(transfer.trait_path.as_deref(), Some("token :: Token"));
    }

    #[test]
    fn inventories_contracttype_and_contracterror() {
        let src = r#"
#[contracttype]
pub struct Config {
    pub admin: Address,
}

#[contracttype]
pub enum DataKey {
    Admin,
    Balance(Address),
}

#[contracterror]
pub enum VaultError {
    NotInitialized = 1,
    Unauthorized = 2,
}

struct Plain;
"#;
        let s = parse(src);
        assert_eq!(s.contract_types.len(), 3);

        let config = s
            .contract_types
            .iter()
            .find(|ty| ty.name == "Config")
            .unwrap();
        assert_eq!(config.kind, ContractTypeKind::Struct);
        assert!(config.is_public);
        assert!(config.attributes.iter().any(|a| a == "contracttype"));
        assert!(config.variants.is_empty());
        assert_eq!(config.line, 2);

        let key = s
            .contract_types
            .iter()
            .find(|ty| ty.name == "DataKey")
            .unwrap();
        assert_eq!(key.kind, ContractTypeKind::Enum);
        assert_eq!(key.variants, vec!["Admin", "Balance"]);

        let error = s
            .contract_types
            .iter()
            .find(|ty| ty.name == "VaultError")
            .unwrap();
        assert_eq!(error.kind, ContractTypeKind::Enum);
        assert_eq!(error.variants, vec!["NotInitialized", "Unauthorized"]);
        assert!(error.attributes.iter().any(|a| a == "contracterror"));

        assert!(!s.contract_types.iter().any(|ty| ty.name == "Plain"));
    }

    #[test]
    fn inventories_qualified_contract_type_attributes() {
        let src = r#"
#[soroban_sdk::contracttype]
pub struct Config {
    pub admin: Address,
}
"#;
        let s = parse(src);
        assert_eq!(s.contract_types.len(), 1);
        assert_eq!(s.contract_types[0].name, "Config");
    }

    #[test]
    fn fixture_inventories_contract_types() {
        let s = parse(include_str!(
            "../../../fixtures/projects/contract-types/src/lib.rs"
        ));
        assert!(s.is_parsed());
        assert!(s
            .contract_types
            .iter()
            .any(|ty| ty.name == "DataKey" && ty.kind == ContractTypeKind::Enum));
        assert!(s
            .contract_types
            .iter()
            .any(|ty| ty.name == "VaultError" && ty.kind == ContractTypeKind::Enum));
        assert!(s
            .contract_types
            .iter()
            .any(|ty| ty.name == "Config" && ty.kind == ContractTypeKind::Struct));
    }

    #[test]
    fn distinguishes_every_function_visibility() {
        let src = r#"
use soroban_sdk::{contract, contractimpl};

#[contract]
pub struct C;

#[contractimpl]
impl C {
    pub fn public_fn() {}
    pub(crate) fn crate_fn() {}
    pub(super) fn super_fn() {}
    pub(self) fn self_fn() {}
    fn private_fn() {}
}
"#;
        let s = parse(src);
        let visibility = |name: &str| {
            s.functions
                .iter()
                .find(|f| f.name == name)
                .unwrap()
                .visibility
        };

        assert_eq!(visibility("public_fn"), Visibility::Public);
        assert_eq!(visibility("crate_fn"), Visibility::Crate);
        assert_eq!(visibility("super_fn"), Visibility::Super);
        assert_eq!(visibility("self_fn"), Visibility::Self_);
        assert_eq!(visibility("private_fn"), Visibility::Inherited);

        let entries: Vec<_> = s.contract_entry_points().map(|f| f.name.as_str()).collect();
        assert_eq!(entries, vec!["public_fn"]);
    }

    #[test]
    fn excludes_cfg_test_items_only_when_requested() {
        let src = r#"
#[contractimpl]
impl C {
    pub fn real(env: Env) {}

    #[cfg(test)]
    pub fn test_helper(env: Env) {}
}

#[cfg(test)]
mod tests {
    #[contractimpl]
    impl C {
        pub fn test_only(env: Env) {}
    }
}

#[cfg(not(test))]
fn available_in_production() {}
"#;
        let kept = parse_source_with_options(Path::new("src/lib.rs"), Path::new("."), src, false);
        let kept_names: Vec<_> = kept.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(kept_names.contains(&"test_helper"));
        assert!(kept_names.contains(&"test_only"));
        assert!(kept_names.contains(&"available_in_production"));

        let pruned = parse_source_with_options(Path::new("src/lib.rs"), Path::new("."), src, true);
        let pruned_names: Vec<_> = pruned.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(pruned_names.contains(&"real"));
        assert!(!pruned_names.contains(&"test_helper"));
        assert!(!pruned_names.contains(&"test_only"));
        assert!(pruned_names.contains(&"available_in_production"));
    }

    #[test]
    fn plain_impl_is_not_contract() {
        let src = "struct C;\nimpl C { pub fn f(&self) {} }\n";
        let s = parse(src);
        assert!(s.contract_definitions.is_empty());
        assert_eq!(s.contract_entry_points().count(), 0);
        assert_eq!(s.functions.len(), 1);
        assert!(!s.functions[0].is_contract_entry_point);
        assert_eq!(s.functions[0].params.len(), 0);
    }

    #[test]
    fn walks_nested_modules() {
        let src = "mod inner { pub fn g() {} }\n";
        let s = parse(src);
        let f = s.functions.iter().find(|f| f.name == "g").unwrap();
        assert_eq!(f.qualified_name, "inner::g");
        assert!(s
            .items
            .iter()
            .any(|i| i.kind == ItemKind::Module && i.name == "inner"));
    }

    #[test]
    fn parse_error_is_recorded_not_panicked() {
        let s = parse("fn broken( {");
        assert!(!s.is_parsed());
        assert!(s.parse_error.is_some());
        assert!(s.functions.is_empty());
    }

    #[test]
    fn module_path_is_computed() {
        let root = Path::new("/proj");
        assert_eq!(
            module_path_for(Path::new("/proj/src/lib.rs"), root),
            "crate"
        );
        assert_eq!(
            module_path_for(Path::new("/proj/src/foo.rs"), root),
            "crate::foo"
        );
        assert_eq!(
            module_path_for(Path::new("/proj/src/foo/mod.rs"), root),
            "crate::foo"
        );
    }

    #[test]
    fn classifies_contract_evidence() {
        let src = "#[contractimpl]\nimpl C { pub fn f() {} }\n";
        let s = parse(src);
        let info = soroban_evidence(&[s]);
        assert!(info.contract_macros_found);
    }

    #[test]
    fn measures_delimiter_depth() {
        assert_eq!(max_delimiter_depth("fn f() { (()) }"), 3);
        assert_eq!(max_delimiter_depth("fn f() {}"), 1);
    }

    #[test]
    fn ignores_delimiters_in_strings_and_comments() {
        assert_eq!(max_delimiter_depth("let s = \"((((((\";"), 0);
        assert_eq!(max_delimiter_depth("// ((((((\n"), 0);
        assert_eq!(max_delimiter_depth("/* (((((( */"), 0);
        assert_eq!(max_delimiter_depth("let r = r#\"(((((\"#;"), 0);
        assert_eq!(max_delimiter_depth("let c = '(';"), 0);
    }

    #[test]
    fn rejects_pathologically_nested_source() {
        let depth = MAX_NESTING_DEPTH + 50;
        let src = format!("fn f() {{ {}0{} }}", "(".repeat(depth), ")".repeat(depth));
        let parsed = parse(&src);
        assert!(parsed.parse_error.is_some());
        assert!(!parsed.is_parsed());
    }

    #[test]
    fn inventories_macro_definitions_and_invocations() {
        let src = concat!(
            "macro_rules! helper { ($value:expr) => { $value }; }\n",
            "fn run() {\n",
            "    helper!(1);\n",
            "    other::call!();\n",
            "}\n",
        );
        let s = parse(src);
        assert_eq!(s.macro_definitions.len(), 1);
        assert_eq!(s.macro_definitions[0].name, "helper");
        assert_eq!(s.macro_definitions[0].line, 1);
        let names: Vec<_> = s
            .macro_invocations
            .iter()
            .map(|invocation| invocation.name.as_str())
            .collect();
        assert_eq!(names, vec!["helper", "other::call"]);
        assert_eq!(s.macro_invocations[0].line, 3);
        assert_eq!(s.macro_invocations[1].line, 4);
    }

    #[test]
    fn loads_the_macro_helper_fixture() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/parser/macro_helper.rs"
        ));
        let content = std::fs::read_to_string(path).unwrap();
        let s = parse(&content);
        assert!(s.is_parsed());
        assert!(s
            .macro_definitions
            .iter()
            .any(|definition| definition.name == "checked_add"));
        assert!(s
            .macro_invocations
            .iter()
            .any(|invocation| invocation.name == "checked_add"));
    }

    #[test]
    fn detects_generated_markers_lexically() {
        let src = concat!(
            "const TEXT: &str = \"@generated\";\n",
            "// @generated by a code generator\n",
            "const INCLUDE: &str = \"include!(\\\"generated.rs\\\")\";\n",
            "// include!(\"not-a-macro.rs\")\n",
            "include!(\"generated.rs\");\n",
            "/*\n",
            " * @generated\n",
            " */\n",
        );
        let s = parse(src);
        assert!(s.is_generated());
        let markers: Vec<_> = s
            .generated_markers
            .iter()
            .map(|marker| (marker.kind, marker.line))
            .collect();
        assert_eq!(
            markers,
            vec![
                (GeneratedMarkerKind::GeneratedComment, 2),
                (GeneratedMarkerKind::IncludeMacro, 5),
                (GeneratedMarkerKind::GeneratedComment, 7),
            ]
        );
    }

    #[test]
    fn loads_the_generated_marker_fixture() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/parser/generated_marker.rs"
        ));
        let content = std::fs::read_to_string(path).unwrap();
        let s = parse(&content);
        assert!(s.is_generated());
        assert!(s
            .generated_markers
            .iter()
            .any(|marker| marker.kind == GeneratedMarkerKind::GeneratedComment));
    }

    #[test]
    fn inventories_const_static_and_const_fn() {
        let src = concat!(
            "pub const LIMIT: u32 = 10 + 2;\n",
            "static NAME: &str = \"vault\";\n",
            "static mut COUNTER: i32 = 0;\n",
            "pub const fn ceiling() -> u32 { LIMIT }\n",
            "impl Vault {\n",
            "    const ASSOC: u64 = 1;\n",
            "}\n",
            "trait T {\n",
            "    const DEFAULT: u8;\n",
            "}\n",
        );
        let s = parse(src);
        let limit = s
            .constants
            .iter()
            .find(|constant| constant.name == "LIMIT")
            .unwrap();
        assert_eq!(limit.kind, ValueKind::Const);
        assert_eq!(limit.ty, "u32");
        assert_eq!(limit.value, "10 + 2");
        assert_eq!(limit.qualified_name, "LIMIT");
        assert_eq!(limit.visibility, Visibility::Public);

        let name = s
            .constants
            .iter()
            .find(|constant| constant.name == "NAME")
            .unwrap();
        assert_eq!(name.kind, ValueKind::Static);
        assert_eq!(name.ty, "& str");
        assert_eq!(name.value, "\"vault\"");

        let counter = s
            .constants
            .iter()
            .find(|constant| constant.name == "COUNTER")
            .unwrap();
        assert_eq!(counter.kind, ValueKind::StaticMut);

        let assoc = s
            .constants
            .iter()
            .find(|constant| constant.name == "ASSOC")
            .unwrap();
        assert_eq!(assoc.qualified_name, "Vault::ASSOC");

        let default = s
            .constants
            .iter()
            .find(|constant| constant.name == "DEFAULT")
            .unwrap();
        assert_eq!(default.value, "");

        let ceiling = s
            .functions
            .iter()
            .find(|function| function.name == "ceiling")
            .unwrap();
        assert!(ceiling.is_const);
        assert_eq!(ceiling.return_type.as_deref(), Some("u32"));
    }
}
