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
use crate::imports::ImportMap;
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
    /// Rendered arguments, in source order.
    pub args: Vec<String>,
    /// Number of arguments in the call.
    ///
    /// Redundant with `args.len()` by construction; exposed explicitly so rule
    /// authors can reason about arity without relying on the rendered list.
    pub arg_count: usize,
    /// 1-based `(line, column)` of each argument, in source order.
    pub arg_positions: Vec<(usize, usize)>,
    /// Rendered call text (may be truncated by consumers).
    pub text: String,
}

impl CallFact {
    /// Returns the rendered argument at `index`, if present.
    pub fn argument(&self, index: usize) -> Option<&str> {
        self.args.get(index).map(String::as_str)
    }
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
    /// How the literal was constructed: `literal`, a macro name such as
    /// `symbol_short`, or a constructor such as `Symbol::new`.
    pub origin: String,
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

/// Where a cast operand comes from, as far as the source shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CastOrigin {
    /// A function parameter.
    Parameter,
    /// A value read from contract storage (directly or through a local).
    StorageRead,
    /// A local variable with a visible type annotation.
    Local,
    /// Anything else, including literals and computed expressions.
    Other,
}

/// A cast fact (`expr as Type`).
///
/// `source_type` is only populated when the source makes it visible: a literal
/// suffix, a local type annotation, a parameter type, or a storage
/// `get::<_, T>` turbofish. No type inference is performed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CastFact {
    /// Rendered operand expression.
    pub source: String,
    /// Rendered source type when visible, otherwise empty.
    pub source_type: String,
    /// Rendered target type.
    pub target_type: String,
    /// Where the operand comes from.
    pub origin: CastOrigin,
    /// 1-based line.
    pub line: usize,
    /// 1-based column.
    pub column: usize,
    /// Rendered cast text (may be truncated).
    pub text: String,
}

/// Returns the bit width of a Rust integer type name, if it is one.
///
/// Accepts a leading reference and a qualified path (`&u32`,
/// `std::primitive::u64`). Soroban's `u256`/`i256` are included; `usize` and
/// `isize` are treated as 64-bit, the Soroban host width.
pub fn integer_bit_width(type_text: &str) -> Option<u32> {
    let text = type_text.trim().trim_start_matches('&').trim();
    let name = text.rsplit("::").next().unwrap_or(text).trim();
    Some(match name {
        "u8" | "i8" => 8,
        "u16" | "i16" => 16,
        "u32" | "i32" => 32,
        "u64" | "i64" | "usize" | "isize" => 64,
        "u128" | "i128" => 128,
        "u256" | "i256" => 256,
        _ => return None,
    })
}

/// Extracts cast facts from a function block.
///
/// `param_types` maps parameter names to their rendered type text (see
/// [`ContractFn::param_types`]). Only casts whose operand type is visible in the
/// source carry a non-empty `source_type`.
pub fn cast_facts(block: &syn::Block, param_types: &BTreeMap<String, String>) -> Vec<CastFact> {
    struct CastVisitor<'a> {
        param_types: &'a BTreeMap<String, String>,
        local_types: BTreeMap<String, String>,
        storage_locals: BTreeSet<String>,
        casts: Vec<CastFact>,
    }

    impl<'ast> Visit<'ast> for CastVisitor<'_> {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let Some(init) = &node.init {
                let binding = match &node.pat {
                    syn::Pat::Ident(pattern) => Some((pattern.ident.to_string(), None)),
                    syn::Pat::Type(typed) => match &*typed.pat {
                        syn::Pat::Ident(pattern) => Some((
                            pattern.ident.to_string(),
                            Some(typed.ty.to_token_stream().to_string()),
                        )),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some((name, explicit)) = binding {
                    let from_storage = is_storage_read(&init.expr);
                    let inferred = storage_value_type(&init.expr);
                    if let Some(ty) = explicit.or(inferred) {
                        self.local_types.insert(name.clone(), ty);
                    }
                    if from_storage {
                        self.storage_locals.insert(name);
                    }
                }
            }
            visit::visit_local(self, node);
        }

        fn visit_expr_cast(&mut self, node: &'ast syn::ExprCast) {
            let (line, column) = span_line_col(node);
            self.casts.push(CastFact {
                source: truncate(&node.expr.to_token_stream().to_string(), 120),
                source_type: source_type_of(&node.expr, self.param_types, &self.local_types)
                    .unwrap_or_default(),
                target_type: node.ty.to_token_stream().to_string(),
                origin: origin_of(
                    &node.expr,
                    self.param_types,
                    &self.local_types,
                    &self.storage_locals,
                ),
                line,
                column,
                text: truncate(&node.to_token_stream().to_string(), 160),
            });
            visit::visit_expr_cast(self, node);
        }
    }

    let mut visitor = CastVisitor {
        param_types,
        local_types: BTreeMap::new(),
        storage_locals: BTreeSet::new(),
        casts: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.casts
}

fn is_storage_read(expr: &syn::Expr) -> bool {
    let text = expr.to_token_stream().to_string().to_ascii_lowercase();
    text.contains("storage") && (text.contains("get") || text.contains("get_unchecked"))
}

/// Finds the value type of a storage `get::<K, V>` call in an expression chain.
fn storage_value_type(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::MethodCall(call) => {
            if call.method == "get" || call.method == "get_unchecked" {
                if let Some(turbofish) = &call.turbofish {
                    return turbofish.args.iter().rev().find_map(|arg| match arg {
                        syn::GenericArgument::Type(ty) => Some(ty.to_token_stream().to_string()),
                        _ => None,
                    });
                }
            }
            storage_value_type(&call.receiver)
        }
        syn::Expr::Try(expr) => storage_value_type(&expr.expr),
        syn::Expr::Await(expr) => storage_value_type(&expr.base),
        _ => None,
    }
}

fn source_type_of(
    expr: &syn::Expr,
    param_types: &BTreeMap<String, String>,
    local_types: &BTreeMap<String, String>,
) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => path.path.get_ident().and_then(|ident| {
            let name = ident.to_string();
            local_types
                .get(&name)
                .or_else(|| param_types.get(&name))
                .cloned()
        }),
        syn::Expr::Reference(expr) => source_type_of(&expr.expr, param_types, local_types),
        syn::Expr::Paren(expr) => source_type_of(&expr.expr, param_types, local_types),
        syn::Expr::Group(expr) => source_type_of(&expr.expr, param_types, local_types),
        syn::Expr::Lit(literal) => match &literal.lit {
            syn::Lit::Int(int) => {
                let suffix = int.suffix();
                (!suffix.is_empty()).then(|| suffix.to_string())
            }
            _ => None,
        },
        _ => storage_value_type(expr),
    }
}

fn origin_of(
    expr: &syn::Expr,
    param_types: &BTreeMap<String, String>,
    local_types: &BTreeMap<String, String>,
    storage_locals: &BTreeSet<String>,
) -> CastOrigin {
    match expr {
        syn::Expr::Path(path) => match path.path.get_ident() {
            Some(ident) => {
                let name = ident.to_string();
                if param_types.contains_key(&name) {
                    CastOrigin::Parameter
                } else if storage_locals.contains(&name) {
                    CastOrigin::StorageRead
                } else if local_types.contains_key(&name) {
                    CastOrigin::Local
                } else {
                    CastOrigin::Other
                }
            }
            None => CastOrigin::Other,
        },
        syn::Expr::Reference(expr) => {
            origin_of(&expr.expr, param_types, local_types, storage_locals)
        }
        syn::Expr::Paren(expr) => origin_of(&expr.expr, param_types, local_types, storage_locals),
        syn::Expr::Group(expr) => origin_of(&expr.expr, param_types, local_types, storage_locals),
        other if is_storage_read(other) => CastOrigin::StorageRead,
        _ => CastOrigin::Other,
    }
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
    /// Local variables initialized from a storage read.
    pub storage_vars: BTreeSet<String>,
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

struct FactsVisitor<'a> {
    facts: Facts,
    imports: &'a ImportMap,
    unsafe_depth: usize,
    client_vars: BTreeSet<String>,
    current_macro: Option<String>,
    current_constructor: Option<String>,
}

impl<'a> FactsVisitor<'a> {
    fn new(imports: &'a ImportMap) -> Self {
        FactsVisitor {
            facts: Facts::default(),
            imports,
            unsafe_depth: 0,
            client_vars: BTreeSet::new(),
            current_macro: None,
            current_constructor: None,
        }
    }
}

fn span_line_col<T: Spanned>(node: &T) -> (usize, usize) {
    let start = node.span().start();
    (start.line, start.column + 1)
}

/// Truncates `text` to at most `max` bytes without splitting a UTF-8 code point.
///
/// Call arguments come from untrusted source, so truncation must never panic on
/// multi-byte characters.
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

fn render_args(
    args: &syn::punctuated::Punctuated<syn::Expr, syn::Token![,]>,
) -> (Vec<String>, Vec<(usize, usize)>) {
    let mut rendered = Vec::with_capacity(args.len());
    let mut positions = Vec::with_capacity(args.len());
    for arg in args {
        rendered.push(truncate(&arg.to_token_stream().to_string(), 120));
        positions.push(span_line_col(arg));
    }
    (rendered, positions)
}

impl<'ast, 'a> Visit<'ast> for FactsVisitor<'a> {
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
        let (args, arg_positions) = render_args(&node.args);
        let fact = CallFact {
            name: node.method.to_string(),
            context: self
                .imports
                .canonicalize(&node.receiver.to_token_stream().to_string()),
            line,
            column,
            start_byte: span.start,
            end_byte: span.end,
            arg_count: args.len(),
            args,
            arg_positions,
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
                    let context = self
                        .imports
                        .canonicalize(&path.path.to_token_stream().to_string());
                    if name == "new" && context.contains("Client") {
                        self.client_vars.insert(pattern.ident.to_string());
                    }
                }
            }
            let init_text = init.expr.to_token_stream().to_string().to_ascii_lowercase();
            if init_text.contains("storage") && init_text.contains("get") {
                self.facts.storage_vars.insert(pattern.ident.to_string());
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let previous_constructor = self.current_constructor.clone();
        if let syn::Expr::Path(path) = &*node.func {
            let (line, column) = span_line_col(node);
            let name = path
                .path
                .segments
                .last()
                .map(|s| s.ident.to_string())
                .unwrap_or_default();
            let span = node.span().byte_range();
            let (args, arg_positions) = render_args(&node.args);
            let context = self
                .imports
                .canonicalize(&path.path.to_token_stream().to_string());
            if name == "new" && context.contains("Symbol") {
                self.current_constructor = Some("Symbol::new".to_string());
            }
            self.facts.function_calls.push(CallFact {
                name,
                context: context.clone(),
                line,
                column,
                start_byte: span.start,
                end_byte: span.end,
                arg_count: args.len(),
                args,
                arg_positions,
                text: truncate(&node.to_token_stream().to_string(), 160),
            });
        }
        visit::visit_expr_call(self, node);
        self.current_constructor = previous_constructor;
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
            name: name.clone(),
            line,
            column,
            text: truncate(&node.to_token_stream().to_string(), 160),
        });
        // Macro token streams are opaque to the AST visitor, so capture the
        // literal directly for the Soroban symbol macros.
        if name == "symbol_short" || name == "symbol" {
            let raw = node.tokens.to_string();
            let value = raw.trim().trim_matches('"').to_string();
            if !value.is_empty() {
                self.facts.strings.push(StringFact {
                    value,
                    line,
                    column,
                    origin: name.clone(),
                });
            }
        }
        let previous_macro = self.current_macro.replace(name);
        visit::visit_macro(self, node);
        self.current_macro = previous_macro;
    }

    fn visit_lit(&mut self, node: &'ast syn::Lit) {
        if let syn::Lit::Str(s) = node {
            let (line, column) = span_line_col(node);
            self.facts.strings.push(StringFact {
                value: s.value(),
                line,
                column,
                origin: self
                    .current_constructor
                    .clone()
                    .or_else(|| self.current_macro.clone())
                    .unwrap_or_else(|| "literal".to_string()),
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
    facts_from_block_with_imports(block, &ImportMap::default())
}

/// Extracts facts from a block, canonicalizing path contexts with `imports`.
pub fn facts_from_block_with_imports(block: &syn::Block, imports: &ImportMap) -> Facts {
    let mut visitor = FactsVisitor::new(imports);
    visitor.visit_block(block);
    visitor.facts
}

/// Extracts facts from a whole file.
pub fn facts_from_file(file: &syn::File) -> Facts {
    facts_from_file_with_imports(file, &ImportMap::default())
}

/// Extracts facts from a whole file, canonicalizing path contexts with `imports`.
pub fn facts_from_file_with_imports(file: &syn::File, imports: &ImportMap) -> Facts {
    let mut visitor = FactsVisitor::new(imports);
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
    function_facts_with_imports(file, &ImportMap::default())
}

/// Like [`function_facts`] but canonicalizes contexts with `imports`.
pub fn function_facts_with_imports(
    file: &syn::File,
    imports: &ImportMap,
) -> BTreeMap<String, Facts> {
    let mut map = BTreeMap::new();
    collect_function_facts(&file.items, imports, &mut map);
    map
}

fn collect_function_facts(
    items: &[syn::Item],
    imports: &ImportMap,
    out: &mut BTreeMap<String, Facts>,
) {
    for item in items {
        match item {
            syn::Item::Fn(f) => {
                out.entry(f.sig.ident.to_string())
                    .or_insert_with(|| facts_from_block_with_imports(&f.block, imports));
            }
            syn::Item::Impl(imp) => {
                for impl_item in &imp.items {
                    if let syn::ImplItem::Fn(f) = impl_item {
                        out.entry(f.sig.ident.to_string())
                            .or_insert_with(|| facts_from_block_with_imports(&f.block, imports));
                    }
                }
            }
            syn::Item::Mod(m) => {
                if let Some((_, sub)) = &m.content {
                    collect_function_facts(sub, imports, out);
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
    facts_with_helpers_with_imports(file, entry, &ImportMap::default())
}

/// Like [`facts_with_helpers`] but canonicalizes contexts with `imports`.
pub fn facts_with_helpers_with_imports(
    file: &syn::File,
    entry: &ContractFn<'_>,
    imports: &ImportMap,
) -> Facts {
    let summaries = function_facts_with_imports(file, imports);
    facts_with_helpers_from_with_imports(&summaries, entry, imports)
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
    facts_with_helpers_from_with_imports(summaries, entry, &ImportMap::default())
}

/// Like [`facts_with_helpers_from`] but canonicalizes the entry point with
/// `imports`.
pub fn facts_with_helpers_from_with_imports(
    summaries: &BTreeMap<String, Facts>,
    entry: &ContractFn<'_>,
    imports: &ImportMap,
) -> Facts {
    let mut merged = facts_from_block_with_imports(entry.block, imports);
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
    /// Parameter names with their rendered type text, in declaration order.
    ///
    /// Only plain identifier patterns are recorded. The type text is exactly as
    /// written in the signature (for example `u32`, `&Env`), so rules can do
    /// conservative checks without type inference.
    pub param_types: Vec<(String, String)>,
    /// 1-based `(line, column)` of each entry in `param_types`, in the same
    /// order.
    pub param_spans: Vec<(usize, usize)>,
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

/// Collects parameter names and rendered type text of a function signature.
fn parameter_types(sig: &syn::Signature) -> Vec<(String, String)> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
                syn::Pat::Ident(pat_ident) => Some((
                    pat_ident.ident.to_string(),
                    pat_type.ty.to_token_stream().to_string(),
                )),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

/// Collects the 1-based `(line, column)` of each parameter recorded by
/// [`parameter_types`].
fn parameter_spans(sig: &syn::Signature) -> Vec<(usize, usize)> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
                syn::Pat::Ident(_) => Some(span_line_col(&*pat_type.pat)),
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
                            param_types: parameter_types(&f.sig),
                            param_spans: parameter_spans(&f.sig),
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
    fn records_string_literal_origin() {
        let facts = facts_of(
            r#"fn f(env: Env) {
                let a = symbol_short!("key");
                let b = Symbol::new(&env, "other");
                let c = "plain";
            }"#,
        );
        let origins: Vec<_> = facts.strings.iter().map(|s| s.origin.as_str()).collect();
        assert!(origins.contains(&"symbol_short"));
        assert!(origins.contains(&"Symbol::new"));
        assert!(origins.contains(&"literal"));
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
    fn captures_method_call_argument_metadata() {
        let facts = facts_of(
            "fn f(env: Env, to: Address, amount: i128) { client.transfer(to, amount, memo); }",
        );
        let call = &facts.method_calls[0];
        assert_eq!(call.name, "transfer");
        assert_eq!(call.arg_count, 3);
        assert_eq!(call.args, vec!["to", "amount", "memo"]);
        assert_eq!(call.argument(0), Some("to"));
        assert_eq!(call.argument(2), Some("memo"));
        assert_eq!(call.argument(3), None);
        assert_eq!(call.arg_positions.len(), 3);
        assert_eq!(call.arg_positions[0].0, 1);
        assert!(call.arg_positions[1].1 > call.arg_positions[0].1);
    }

    #[test]
    fn captures_function_call_argument_metadata() {
        let facts = facts_of("fn f() { transfer(&env, &from, &to, amount); }");
        let call = &facts.function_calls[0];
        assert_eq!(call.name, "transfer");
        assert_eq!(call.arg_count, 4);
        assert_eq!(call.args, vec!["& env", "& from", "& to", "amount"]);
        assert_eq!(call.arg_positions.len(), 4);
    }

    #[test]
    fn call_argument_rendering_truncates_safely() {
        let long = "a".repeat(200);
        let src = format!("fn f() {{ g({long}, \"ééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé\"); }}");
        let facts = facts_of(&src);
        let call = &facts.function_calls[0];
        assert_eq!(call.arg_count, 2);
        assert!(call.args[0].ends_with("..."));
        assert!(call.args[0].len() <= 123);
        assert!(call.args[1].ends_with("..."));
        assert!(call.args[1].is_char_boundary(call.args[1].len() - 3));
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

    #[test]
    fn records_cast_source_and_target_types() {
        let block = syn::parse_file(
            r#"
            fn f(env: Env, amount: i128) {
                let stored: u64 = env.storage().instance().get(&K).unwrap();
                let _ = amount as u32;
                let _ = stored as u32;
                let local: u32 = 1;
                let _ = local as u8;
                let _ = 1u64 as u32;
            }
            "#,
        )
        .unwrap();
        let syn::Item::Fn(function) = &block.items[0] else {
            panic!("expected a function");
        };
        let params: BTreeMap<String, String> = [("amount".to_string(), "i128".to_string())]
            .into_iter()
            .collect();
        let casts = cast_facts(&function.block, &params);
        assert_eq!(casts.len(), 4);
        assert_eq!(casts[0].source_type, "i128");
        assert_eq!(casts[0].target_type, "u32");
        assert_eq!(casts[0].origin, CastOrigin::Parameter);
        assert_eq!(casts[1].source_type, "u64");
        assert_eq!(casts[1].origin, CastOrigin::StorageRead);
        assert_eq!(casts[2].source_type, "u32");
        assert_eq!(casts[2].origin, CastOrigin::Local);
        assert_eq!(casts[3].source_type, "u64");
        assert_eq!(casts[3].origin, CastOrigin::Other);
    }

    #[test]
    fn resolves_storage_read_types_from_turbofish() {
        let block = syn::parse_file(
            r#"
            fn f(env: Env) {
                let stored = env.storage().instance().get::<_, u64>(&K).unwrap();
                let _ = stored as u32;
            }
            "#,
        )
        .unwrap();
        let syn::Item::Fn(function) = &block.items[0] else {
            panic!("expected a function");
        };
        let casts = cast_facts(&function.block, &BTreeMap::new());
        assert_eq!(casts[0].source_type, "u64");
        assert_eq!(casts[0].origin, CastOrigin::StorageRead);
    }

    #[test]
    fn recognizes_integer_widths() {
        assert_eq!(integer_bit_width("u8"), Some(8));
        assert_eq!(integer_bit_width("&u32"), Some(32));
        assert_eq!(integer_bit_width("std::primitive::i128"), Some(128));
        assert_eq!(integer_bit_width("u256"), Some(256));
        assert_eq!(integer_bit_width("usize"), Some(64));
        assert_eq!(integer_bit_width("bool"), None);
        assert_eq!(integer_bit_width("Address"), None);
    }
}
