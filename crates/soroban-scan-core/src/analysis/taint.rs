//! Bounded, data-only taint vocabulary for user-controlled data.
//!
//! The module defines source and sink descriptors that rule authors can
//! register and query, plus a small propagation pass that connects function
//! parameters and decoded inputs to authorization subjects and token transfer
//! amounts. Nothing here executes project code. Every result is derived from
//! the parsed source, capped, and ordered deterministically.
//!
//! When a value has more than one tainted origin, or a helper cannot be followed
//! to the configured depth, the result carries [`TaintPath::Unknown`] rather
//! than a guessed path.
//!
//! See `docs/taint-analysis.md` for the descriptor vocabulary and the documented
//! sanitizers.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::rules::util::ContractFn;

/// Maximum number of source descriptors one registration accepts.
pub const MAX_SOURCES: usize = 64;
/// Maximum number of sink descriptors one registration accepts.
pub const MAX_SINKS: usize = 64;
/// Maximum number of steps retained in a recorded path.
pub const MAX_PATH_STEPS: usize = 4;
/// Maximum length of a descriptor name.
pub const MAX_NAME_LEN: usize = 96;
/// Maximum rendered expression length retained in a path.
pub const MAX_EXPRESSION_LEN: usize = 120;
/// Maximum number of intra-file helpers followed from one entry point.
pub const MAX_HELPERS: usize = 32;
/// Maximum helper recursion depth.
pub const MAX_HELPER_DEPTH: usize = 3;
/// Maximum fixed-point propagation passes.
pub const MAX_ITERATIONS: usize = 32;
/// Maximum number of flows returned for one entry point.
pub const MAX_FLOWS: usize = 64;

/// Kinds of user-controlled source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    /// A contract function parameter other than the `Env`.
    FunctionParameter,
    /// A value decoded from caller-supplied input.
    DecodedInput,
}

impl SourceKind {
    /// Stable lowercase name used in documentation and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::FunctionParameter => "function_parameter",
            SourceKind::DecodedInput => "decoded_input",
        }
    }
}

/// Kinds of security sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SinkKind {
    /// The subject passed to `require_auth` / `require_auth_for_args`.
    AuthSubject,
    /// The amount argument of `transfer` / `transfer_from`.
    TransferAmount,
}

impl SinkKind {
    /// Stable lowercase name used in documentation and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            SinkKind::AuthSubject => "auth_subject",
            SinkKind::TransferAmount => "transfer_amount",
        }
    }
}

/// A 1-based source span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    /// 1-based start line.
    pub line: usize,
    /// 1-based start column.
    pub column: usize,
    /// 1-based end line.
    pub end_line: usize,
    /// 1-based end column.
    pub end_column: usize,
}

impl Span {
    /// Creates a span whose end equals its start.
    pub fn at(line: usize, column: usize) -> Self {
        Span {
            line,
            column,
            end_line: line,
            end_column: column,
        }
    }

    /// Sets the end position.
    pub fn with_end(mut self, line: usize, column: usize) -> Self {
        self.end_line = line;
        self.end_column = column;
        self
    }

    fn is_valid(self) -> bool {
        self.line > 0
            && self.column > 0
            && self.end_line > 0
            && self.end_column > 0
            && (self.end_line, self.end_column) >= (self.line, self.column)
    }
}

/// A data-only description of a user-controlled source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDescriptor {
    /// Identifier or path the source is bound to.
    pub name: String,
    /// What kind of source it is.
    pub kind: SourceKind,
    /// Where the source appears.
    pub span: Span,
}

impl SourceDescriptor {
    /// Validates the descriptor without looking at any other descriptor.
    pub fn validate(&self) -> Result<(), DescriptorError> {
        validate_name(&self.name)?;
        if !self.span.is_valid() {
            return Err(DescriptorError::InvalidSpan);
        }
        Ok(())
    }
}

/// A data-only description of a security sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkDescriptor {
    /// Method or function name.
    pub name: String,
    /// What kind of sink it is.
    pub kind: SinkKind,
    /// Zero-based argument index for call-style sinks; `None` means the
    /// receiver (the authorization subject of `subject.require_auth()`).
    pub argument: Option<usize>,
    /// Where the sink appears.
    pub span: Span,
}

impl SinkDescriptor {
    /// Validates the descriptor without looking at any other descriptor.
    pub fn validate(&self) -> Result<(), DescriptorError> {
        validate_name(&self.name)?;
        if !self.span.is_valid() {
            return Err(DescriptorError::InvalidSpan);
        }
        if self.argument.is_some_and(|index| index > MAX_SOURCES) {
            return Err(DescriptorError::InvalidArgument);
        }
        Ok(())
    }
}

fn validate_name(name: &str) -> Result<(), DescriptorError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(DescriptorError::EmptyName);
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(DescriptorError::NameTooLong);
    }
    if trimmed.chars().any(char::is_control) {
        return Err(DescriptorError::InvalidName);
    }
    Ok(())
}

/// A rejected descriptor registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorError {
    /// The descriptor name is empty or whitespace-only.
    EmptyName,
    /// The descriptor name is longer than [`MAX_NAME_LEN`].
    NameTooLong,
    /// The descriptor name contains control characters.
    InvalidName,
    /// The span is zero or ends before it starts.
    InvalidSpan,
    /// The sink argument index is out of range.
    InvalidArgument,
    /// Registering the descriptor would exceed [`MAX_SOURCES`].
    SourceLimit,
    /// Registering the descriptor would exceed [`MAX_SINKS`].
    SinkLimit,
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            DescriptorError::EmptyName => "descriptor name is empty",
            DescriptorError::NameTooLong => "descriptor name is too long",
            DescriptorError::InvalidName => "descriptor name contains control characters",
            DescriptorError::InvalidSpan => "descriptor span is invalid",
            DescriptorError::InvalidArgument => "sink argument index is out of range",
            DescriptorError::SourceLimit => "source descriptor limit reached",
            DescriptorError::SinkLimit => "sink descriptor limit reached",
        };
        f.write_str(text)
    }
}

impl std::error::Error for DescriptorError {}

/// A bounded registry of source and sink descriptors.
///
/// Registration is data-only: descriptors are values, so a rule pack cannot
/// smuggle in callbacks or other executable behavior. Duplicate descriptors are
/// ignored, and every query returns descriptors in a stable order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DescriptorRegistry {
    sources: Vec<SourceDescriptor>,
    sinks: Vec<SinkDescriptor>,
}

impl DescriptorRegistry {
    /// Registers one source descriptor.
    pub fn register_source(&mut self, descriptor: SourceDescriptor) -> Result<(), DescriptorError> {
        descriptor.validate()?;
        if self.sources.len() >= MAX_SOURCES {
            return Err(DescriptorError::SourceLimit);
        }
        if !self.sources.contains(&descriptor) {
            self.sources.push(descriptor);
            self.sources.sort_by(source_order);
        }
        Ok(())
    }

    /// Registers one sink descriptor.
    pub fn register_sink(&mut self, descriptor: SinkDescriptor) -> Result<(), DescriptorError> {
        descriptor.validate()?;
        if self.sinks.len() >= MAX_SINKS {
            return Err(DescriptorError::SinkLimit);
        }
        if !self.sinks.contains(&descriptor) {
            self.sinks.push(descriptor);
            self.sinks.sort_by(sink_order);
        }
        Ok(())
    }

    /// All registered sources in stable order.
    pub fn sources(&self) -> &[SourceDescriptor] {
        &self.sources
    }

    /// All registered sinks in stable order.
    pub fn sinks(&self) -> &[SinkDescriptor] {
        &self.sinks
    }

    /// Sources of one kind in stable order.
    pub fn sources_of_kind(&self, kind: SourceKind) -> impl Iterator<Item = &SourceDescriptor> {
        self.sources
            .iter()
            .filter(move |source| source.kind == kind)
    }

    /// Sinks of one kind in stable order.
    pub fn sinks_of_kind(&self, kind: SinkKind) -> impl Iterator<Item = &SinkDescriptor> {
        self.sinks.iter().filter(move |sink| sink.kind == kind)
    }
}

fn source_order(a: &SourceDescriptor, b: &SourceDescriptor) -> std::cmp::Ordering {
    (a.span, a.kind, a.name.as_str()).cmp(&(b.span, b.kind, b.name.as_str()))
}

fn sink_order(a: &SinkDescriptor, b: &SinkDescriptor) -> std::cmp::Ordering {
    (a.span, a.kind, a.name.as_str(), a.argument).cmp(&(
        b.span,
        b.kind,
        b.name.as_str(),
        b.argument,
    ))
}

/// Where a tainted value came from and how it reached a sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaintPath {
    /// The value is the source itself.
    Direct {
        /// Source identifier.
        source: String,
    },
    /// The value is an alias of a source.
    Alias {
        /// Source identifier.
        source: String,
        /// Bounded alias hops.
        steps: Vec<String>,
    },
    /// The value is a visible transformation of a source (for example
    /// `amount - 1` or a helper call).
    Transformed {
        /// Source identifier.
        source: String,
        /// Bounded rendered expression.
        expression: String,
    },
    /// The value is tainted but its path could not be established. The value is
    /// still reported; the marker records the ambiguity instead of guessing.
    Unknown {
        /// Bounded explanation.
        reason: String,
    },
}

impl TaintPath {
    /// The source identifier, when the path is concrete.
    pub fn source_name(&self) -> Option<&str> {
        match self {
            TaintPath::Direct { source }
            | TaintPath::Alias { source, .. }
            | TaintPath::Transformed { source, .. } => Some(source),
            TaintPath::Unknown { .. } => None,
        }
    }

    /// A bounded human-readable description of the path.
    pub fn description(&self) -> String {
        match self {
            TaintPath::Direct { source } => source.clone(),
            TaintPath::Alias { source, steps } => {
                format!("{source} via {}", steps.join(" -> "))
            }
            TaintPath::Transformed { source, expression } => {
                format!("{source} transformed as `{expression}`")
            }
            TaintPath::Unknown { reason } => format!("unknown: {reason}"),
        }
    }

    fn unknown(reason: &str) -> Self {
        TaintPath::Unknown {
            reason: truncate(reason, MAX_EXPRESSION_LEN),
        }
    }
}

/// A tainted authorization subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthFlow {
    /// The authorization sink.
    pub sink: SinkDescriptor,
    /// How user-controlled data reached the subject.
    pub path: TaintPath,
}

/// A transfer amount with caller-controlled provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmountFlow {
    /// The transfer sink.
    pub sink: SinkDescriptor,
    /// How user-controlled data reached the amount.
    pub path: TaintPath,
}

impl AmountFlow {
    /// The visible arithmetic or helper expression, when one was recorded.
    pub fn transformation(&self) -> Option<&str> {
        match &self.path {
            TaintPath::Transformed { expression, .. } => Some(expression),
            _ => None,
        }
    }
}

/// Method/function names treated as documented sanitizers for authorization
/// subjects.
pub const AUTH_SANITIZERS: &[&str] = &[
    "validate_address",
    "normalize_address",
    "checked_address",
    "verified_address",
    "sanitize_address",
];

/// Method/function names treated as documented validation or clamping helpers
/// for token amounts.
pub const AMOUNT_SANITIZERS: &[&str] = &[
    "checked_add",
    "checked_sub",
    "checked_mul",
    "checked_div",
    "checked_neg",
    "try_from",
    "try_into",
    "clamp",
    "min",
    "max",
    "validate_amount",
    "checked_amount",
    "verified_amount",
];

/// Deserialization constructors that introduce decoded inputs.
const DECODERS: &[&str] = &[
    "from_xdr",
    "from_bytes",
    "from_string",
    "from_str",
    "try_from",
];

#[derive(Clone)]
struct ParamInfo {
    name: String,
    ty: String,
    span: Span,
}

#[derive(Clone)]
struct Body<'a> {
    name: String,
    params: Vec<ParamInfo>,
    block: &'a syn::Block,
}

fn collect_bodies(file: &syn::File) -> BTreeMap<String, Body<'_>> {
    let mut bodies = BTreeMap::new();
    collect_body_items(&file.items, &mut bodies);
    bodies
}

fn collect_body_items<'a>(items: &'a [syn::Item], out: &mut BTreeMap<String, Body<'a>>) {
    for item in items {
        match item {
            syn::Item::Fn(function) => {
                let name = function.sig.ident.to_string();
                out.entry(name.clone()).or_insert_with(|| Body {
                    name,
                    params: param_infos(&function.sig),
                    block: &function.block,
                });
            }
            syn::Item::Impl(imp) => {
                for impl_item in &imp.items {
                    if let syn::ImplItem::Fn(function) = impl_item {
                        let name = function.sig.ident.to_string();
                        out.entry(name.clone()).or_insert_with(|| Body {
                            name,
                            params: param_infos(&function.sig),
                            block: &function.block,
                        });
                    }
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_body_items(nested, out);
                }
            }
            _ => {}
        }
    }
}

fn param_infos(sig: &syn::Signature) -> Vec<ParamInfo> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            syn::FnArg::Typed(pat_type) => match &*pat_type.pat {
                syn::Pat::Ident(pattern) => Some(ParamInfo {
                    name: pattern.ident.to_string(),
                    ty: pat_type.ty.to_token_stream().to_string(),
                    span: span_of(&*pat_type.pat),
                }),
                _ => None,
            },
            syn::FnArg::Receiver(_) => None,
        })
        .collect()
}

fn span_of<T: Spanned>(node: &T) -> Span {
    let start = node.span().start();
    let end = node.span().end();
    Span::at(start.line, start.column + 1).with_end(end.line, end.column + 1)
}

fn is_env_type(type_text: &str) -> bool {
    type_text
        .trim()
        .trim_start_matches('&')
        .trim()
        .starts_with("Env")
}

fn is_sanitizer(name: &str, sanitizers: &[&str]) -> bool {
    sanitizers.contains(&name)
}

fn callee_name(expr: &syn::Expr) -> Option<String> {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

/// Computes the taint path of an expression against a set of tainted locals.
fn taint_of_expr(
    expr: &syn::Expr,
    tainted: &BTreeMap<String, TaintPath>,
    sanitizers: &[&str],
) -> Option<TaintPath> {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .get_ident()
            .and_then(|ident| tainted.get(&ident.to_string()).cloned()),
        syn::Expr::Reference(inner) => taint_of_expr(&inner.expr, tainted, sanitizers),
        syn::Expr::Paren(inner) => taint_of_expr(&inner.expr, tainted, sanitizers),
        syn::Expr::Group(inner) => taint_of_expr(&inner.expr, tainted, sanitizers),
        syn::Expr::Cast(inner) => taint_of_expr(&inner.expr, tainted, sanitizers),
        syn::Expr::Try(inner) => taint_of_expr(&inner.expr, tainted, sanitizers),
        syn::Expr::Await(inner) => taint_of_expr(&inner.base, tainted, sanitizers),
        syn::Expr::Unary(inner) => taint_of_expr(&inner.expr, tainted, sanitizers),
        syn::Expr::Field(inner) => taint_of_expr(&inner.base, tainted, sanitizers)
            .map(|path| transformed(path, &inner.to_token_stream().to_string())),
        syn::Expr::Index(inner) => taint_of_expr(&inner.expr, tainted, sanitizers)
            .map(|path| transformed(path, &inner.to_token_stream().to_string())),
        syn::Expr::Binary(inner) => combine(
            [
                taint_of_expr(&inner.left, tainted, sanitizers),
                taint_of_expr(&inner.right, tainted, sanitizers),
            ],
            &inner.to_token_stream().to_string(),
        ),
        syn::Expr::MethodCall(call) => {
            let name = call.method.to_string();
            if is_sanitizer(&name, sanitizers) {
                return None;
            }
            let mut paths = vec![taint_of_expr(&call.receiver, tainted, sanitizers)];
            paths.extend(
                call.args
                    .iter()
                    .map(|arg| taint_of_expr(arg, tainted, sanitizers)),
            );
            combine(paths, &call.to_token_stream().to_string())
        }
        syn::Expr::Call(call) => {
            let name = callee_name(&call.func);
            if name
                .as_deref()
                .is_some_and(|name| is_sanitizer(name, sanitizers))
            {
                return None;
            }
            let paths: Vec<_> = call
                .args
                .iter()
                .map(|arg| taint_of_expr(arg, tainted, sanitizers))
                .collect();
            combine(paths, &call.to_token_stream().to_string())
        }
        _ => None,
    }
}

/// Merges taint from several operands. More than one distinct source is
/// recorded as unknown instead of selecting one.
fn combine(
    paths: impl IntoIterator<Item = Option<TaintPath>>,
    expression: &str,
) -> Option<TaintPath> {
    let mut concrete: Vec<TaintPath> = Vec::new();
    let mut unknown = false;
    for path in paths.into_iter().flatten() {
        if matches!(path, TaintPath::Unknown { .. }) {
            unknown = true;
        } else {
            concrete.push(path);
        }
    }
    let sources: BTreeSet<&str> = concrete.iter().filter_map(TaintPath::source_name).collect();
    match (sources.len(), unknown) {
        (0, false) => None,
        (0, true) => Some(TaintPath::unknown(
            "derived from an untracked tainted value",
        )),
        (1, _) => concrete
            .into_iter()
            .next()
            .map(|path| transformed(path, expression)),
        _ => Some(TaintPath::unknown("derived from multiple tainted sources")),
    }
}

fn transformed(path: TaintPath, expression: &str) -> TaintPath {
    match path.source_name() {
        Some(source) => TaintPath::Transformed {
            source: source.to_string(),
            expression: truncate(expression, MAX_EXPRESSION_LEN),
        },
        None => TaintPath::unknown("derived from an untracked tainted value"),
    }
}

fn add_step(path: TaintPath, step: &str) -> TaintPath {
    match path {
        TaintPath::Direct { source } => TaintPath::Alias {
            source,
            steps: vec![step.to_string()],
        },
        TaintPath::Alias { source, mut steps } => {
            if steps.len() >= MAX_PATH_STEPS {
                TaintPath::unknown("helper path exceeds the recorded depth")
            } else {
                steps.push(step.to_string());
                TaintPath::Alias { source, steps }
            }
        }
        TaintPath::Transformed { source, expression } => TaintPath::Alias {
            source,
            steps: vec![step.to_string(), expression],
        },
        TaintPath::Unknown { reason } => TaintPath::Unknown { reason },
    }
}

fn seeds_for(params: &[ParamInfo]) -> BTreeMap<String, TaintPath> {
    params
        .iter()
        .filter(|param| !is_env_type(&param.ty))
        .map(|param| {
            (
                param.name.clone(),
                TaintPath::Direct {
                    source: param.name.clone(),
                },
            )
        })
        .collect()
}

struct PropagationVisitor<'a> {
    tainted: &'a mut BTreeMap<String, TaintPath>,
    sanitizers: &'a [&'a str],
}

impl PropagationVisitor<'_> {
    fn assign(&mut self, name: &str, value: Option<TaintPath>) {
        match value {
            Some(path) => {
                if let Some(existing) = self.tainted.get(name) {
                    if existing != &path && existing.source_name() != path.source_name() {
                        self.tainted.insert(
                            name.to_string(),
                            TaintPath::unknown("reassigned from more than one tainted origin"),
                        );
                        return;
                    }
                }
                self.tainted.insert(name.to_string(), path);
            }
            None => {
                self.tainted.remove(name);
            }
        }
    }
}

fn path_name(expr: &syn::Expr) -> Option<&syn::Ident> {
    match expr {
        syn::Expr::Path(path) if path.qself.is_none() => path.path.get_ident(),
        _ => None,
    }
}

impl<'ast> Visit<'ast> for PropagationVisitor<'_> {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
            let value = taint_of_expr(&init.expr, self.tainted, self.sanitizers);
            self.assign(&pattern.ident.to_string(), value);
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(name) = path_name(&node.left) {
            let value = taint_of_expr(&node.right, self.tainted, self.sanitizers);
            self.assign(&name.to_string(), value);
        }
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let compound = matches!(
            node.op,
            syn::BinOp::AddAssign(_)
                | syn::BinOp::SubAssign(_)
                | syn::BinOp::MulAssign(_)
                | syn::BinOp::DivAssign(_)
                | syn::BinOp::RemAssign(_)
        );
        if compound {
            if let Some(name) = path_name(&node.left) {
                let value = taint_of_expr(&node.right, self.tainted, self.sanitizers)
                    .or_else(|| taint_of_expr(&node.left, self.tainted, self.sanitizers))
                    .map(|path| transformed(path, &node.to_token_stream().to_string()));
                self.assign(&name.to_string(), value);
            }
        }
        visit::visit_expr_binary(self, node);
    }
}

/// Propagates taint through local bindings and assignments until stable.
fn propagate(
    block: &syn::Block,
    seeds: &BTreeMap<String, TaintPath>,
    sanitizers: &[&str],
) -> BTreeMap<String, TaintPath> {
    let mut current = seeds.clone();
    for _ in 0..MAX_ITERATIONS {
        let mut next = seeds.clone();
        let mut visitor = PropagationVisitor {
            tainted: &mut next,
            sanitizers,
        };
        visitor.visit_block(block);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn sink_span(expr: &syn::Expr) -> Span {
    span_of(expr)
}

struct SinkVisitor<'a> {
    tainted: &'a BTreeMap<String, TaintPath>,
    sanitizers: &'a [&'a str],
    kind: SinkKind,
    flows: Vec<(SinkDescriptor, TaintPath)>,
}

impl SinkVisitor<'_> {
    fn push(&mut self, name: &str, argument: Option<usize>, expr: &syn::Expr, path: TaintPath) {
        if self.flows.len() >= MAX_FLOWS {
            return;
        }
        self.flows.push((
            SinkDescriptor {
                name: name.to_string(),
                kind: self.kind,
                argument,
                span: sink_span(expr),
            },
            path,
        ));
    }
}

impl<'ast> Visit<'ast> for SinkVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        match self.kind {
            SinkKind::AuthSubject if name == "require_auth" || name == "require_auth_for_args" => {
                if let Some(path) = taint_of_expr(&node.receiver, self.tainted, self.sanitizers) {
                    self.push(&name, None, &node.receiver, path);
                }
            }
            SinkKind::TransferAmount if name == "transfer" || name == "transfer_from" => {
                if let Some(amount) = node.args.last() {
                    if let Some(path) = taint_of_expr(amount, self.tainted, self.sanitizers) {
                        let index = node.args.len().saturating_sub(1);
                        self.push(&name, Some(index), amount, path);
                    }
                }
            }
            _ => {}
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(name) = callee_name(&node.func) {
            match self.kind {
                SinkKind::AuthSubject
                    if name == "require_auth" || name == "require_auth_for_args" =>
                {
                    if let Some(subject) = node.args.first() {
                        if let Some(path) = taint_of_expr(subject, self.tainted, self.sanitizers) {
                            self.push(&name, Some(0), subject, path);
                        }
                    }
                }
                SinkKind::TransferAmount if name == "transfer" => {
                    if let Some(amount) = node.args.last() {
                        if let Some(path) = taint_of_expr(amount, self.tainted, self.sanitizers) {
                            let index = node.args.len().saturating_sub(1);
                            self.push(&name, Some(index), amount, path);
                        }
                    }
                }
                _ => {}
            }
        }
        visit::visit_expr_call(self, node);
    }
}

fn sinks_in_body(
    block: &syn::Block,
    tainted: &BTreeMap<String, TaintPath>,
    kind: SinkKind,
    sanitizers: &[&str],
) -> Vec<(SinkDescriptor, TaintPath)> {
    let mut visitor = SinkVisitor {
        tainted,
        sanitizers,
        kind,
        flows: Vec::new(),
    };
    visitor.visit_block(block);
    visitor.flows
}

struct CallSite<'a> {
    name: String,
    args: Vec<&'a syn::Expr>,
}

fn calls_in_body<'a>(block: &'a syn::Block) -> Vec<CallSite<'a>> {
    struct CallVisitor<'a> {
        calls: Vec<CallSite<'a>>,
    }

    impl<'ast> Visit<'ast> for CallVisitor<'ast> {
        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Some(name) = callee_name(&node.func) {
                self.calls.push(CallSite {
                    name,
                    args: node.args.iter().collect(),
                });
            }
            visit::visit_expr_call(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.calls.push(CallSite {
                name: node.method.to_string(),
                args: node.args.iter().collect(),
            });
            visit::visit_expr_method_call(self, node);
        }
    }

    let mut visitor = CallVisitor { calls: Vec::new() };
    visitor.visit_block(block);
    visitor.calls
}

fn helper_seeds(
    helper: &Body<'_>,
    call: &CallSite<'_>,
    caller_tainted: &BTreeMap<String, TaintPath>,
    sanitizers: &[&str],
) -> BTreeMap<String, TaintPath> {
    let mut seeds = BTreeMap::new();
    if is_sanitizer(&call.name, sanitizers) {
        return seeds;
    }
    for (index, arg) in call.args.iter().enumerate() {
        let Some(param) = helper.params.get(index) else {
            continue;
        };
        if is_env_type(&param.ty) {
            continue;
        }
        if let Some(path) = taint_of_expr(arg, caller_tainted, sanitizers) {
            let step = format!("{}::{}", call.name, param.name);
            seeds.insert(param.name.clone(), add_step(path, &step));
        }
    }
    seeds
}

struct Analyzer<'a, 'b> {
    bodies: &'a BTreeMap<String, Body<'b>>,
    kind: SinkKind,
    sanitizers: &'a [&'a str],
    visited: BTreeSet<String>,
    flows: Vec<(SinkDescriptor, TaintPath)>,
}

impl<'a, 'b> Analyzer<'a, 'b> {
    fn run(&mut self, body: &Body<'_>, seeds: &BTreeMap<String, TaintPath>, depth: usize) {
        let tainted = propagate(body.block, seeds, self.sanitizers);
        self.flows.extend(sinks_in_body(
            body.block,
            &tainted,
            self.kind,
            self.sanitizers,
        ));

        if depth >= MAX_HELPER_DEPTH || self.visited.len() >= MAX_HELPERS {
            return;
        }
        for call in calls_in_body(body.block) {
            if is_sanitizer(&call.name, self.sanitizers) {
                continue;
            }
            let Some(helper) = self.bodies.get(&call.name).cloned() else {
                continue;
            };
            if !self.visited.insert(helper.name.clone()) {
                continue;
            }
            let seeds = helper_seeds(&helper, &call, &tainted, self.sanitizers);
            if !seeds.is_empty() {
                self.run(&helper, &seeds, depth + 1);
            }
        }
    }
}

fn entry_body<'a>(bodies: &BTreeMap<String, Body<'a>>, entry: &ContractFn<'a>) -> Body<'a> {
    match bodies.get(&entry.name) {
        Some(body) => body.clone(),
        None => Body {
            name: entry.name.clone(),
            params: entry
                .param_types
                .iter()
                .map(|(name, ty)| ParamInfo {
                    name: name.clone(),
                    ty: ty.clone(),
                    span: Span::at(entry.line, entry.column),
                })
                .collect(),
            block: entry.block,
        },
    }
}

fn analyze(
    file: &syn::File,
    entry: &ContractFn<'_>,
    kind: SinkKind,
    sanitizers: &[&str],
) -> Vec<(SinkDescriptor, TaintPath)> {
    let bodies = collect_bodies(file);
    let body = entry_body(&bodies, entry);
    let seeds = seeds_for(&body.params);
    let mut analyzer = Analyzer {
        bodies: &bodies,
        kind,
        sanitizers,
        visited: BTreeSet::from([entry.name.clone()]),
        flows: Vec::new(),
    };
    analyzer.run(&body, &seeds, 0);
    let mut flows = analyzer.flows;
    flows.sort_by(|(a, _), (b, _)| {
        (a.span, a.kind, a.name.as_str(), a.argument).cmp(&(
            b.span,
            b.kind,
            b.name.as_str(),
            b.argument,
        ))
    });
    flows.dedup_by(|(a, _), (b, _)| a == b);
    flows.truncate(MAX_FLOWS);
    flows
}

/// Authorization subjects derived from caller-controlled data in `entry`.
///
/// Values passed through a documented [`AUTH_SANITIZERS`] helper are omitted.
/// Intra-file helpers are followed up to [`MAX_HELPER_DEPTH`].
pub fn auth_subject_flows(file: &syn::File, entry: &ContractFn<'_>) -> Vec<AuthFlow> {
    analyze(file, entry, SinkKind::AuthSubject, AUTH_SANITIZERS)
        .into_iter()
        .map(|(sink, path)| AuthFlow { sink, path })
        .collect()
}

/// Token transfer amounts derived from caller-controlled data in `entry`.
///
/// Values passed through a documented [`AMOUNT_SANITIZERS`] helper are omitted.
/// Arithmetic transformations remain visible in [`AmountFlow::transformation`].
pub fn transfer_amount_flows(file: &syn::File, entry: &ContractFn<'_>) -> Vec<AmountFlow> {
    analyze(file, entry, SinkKind::TransferAmount, AMOUNT_SANITIZERS)
        .into_iter()
        .map(|(sink, path)| AmountFlow { sink, path })
        .collect()
}

/// Source descriptors visible in `entry`, bounded and in source order.
pub fn source_descriptors(file: &syn::File, entry: &ContractFn<'_>) -> Vec<SourceDescriptor> {
    let bodies = collect_bodies(file);
    let body = entry_body(&bodies, entry);
    let seeds = seeds_for(&body.params);
    let tainted = propagate(body.block, &seeds, &[]);
    let mut sources: Vec<SourceDescriptor> = body
        .params
        .iter()
        .filter(|param| !is_env_type(&param.ty))
        .map(|param| SourceDescriptor {
            name: param.name.clone(),
            kind: SourceKind::FunctionParameter,
            span: param.span,
        })
        .collect();

    for (name, span) in decoded_locals(body.block) {
        if tainted.contains_key(&name) {
            sources.push(SourceDescriptor {
                name,
                kind: SourceKind::DecodedInput,
                span,
            });
        }
    }
    sources.sort_by(source_order);
    sources.dedup_by(|a, b| a == b);
    sources.truncate(MAX_SOURCES);
    sources
}

fn decoded_locals(block: &syn::Block) -> Vec<(String, Span)> {
    struct DecodedVisitor {
        locals: Vec<(String, Span)>,
    }

    impl<'ast> Visit<'ast> for DecodedVisitor {
        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
                let text = init.expr.to_token_stream().to_string();
                if DECODERS.iter().any(|name| text.contains(name)) {
                    self.locals
                        .push((pattern.ident.to_string(), span_of(&pattern.ident)));
                }
            }
            visit::visit_local(self, node);
        }
    }

    let mut visitor = DecodedVisitor { locals: Vec::new() };
    visitor.visit_block(block);
    visitor.locals
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
    use crate::rules::util::contract_entry_functions;

    fn entry_of(source: &str) -> (syn::File, usize) {
        let file = syn::parse_file(source).expect("test source must parse");
        let index = contract_entry_functions(&file)
            .iter()
            .position(|function| function.is_public)
            .expect("test source needs a public entry point");
        (file, index)
    }

    fn entry_flags(source: &str) -> (Vec<AuthFlow>, Vec<AmountFlow>) {
        let (file, index) = entry_of(source);
        let entries = contract_entry_functions(&file);
        let entry = &entries[index];
        (
            auth_subject_flows(&file, entry),
            transfer_amount_flows(&file, entry),
        )
    }

    fn descriptor(name: &str, line: usize, column: usize) -> SourceDescriptor {
        SourceDescriptor {
            name: name.to_string(),
            kind: SourceKind::FunctionParameter,
            span: Span::at(line, column),
        }
    }

    #[test]
    fn accepts_valid_descriptors() {
        let source = descriptor("amount", 3, 4);
        assert_eq!(source.validate(), Ok(()));
        let sink = SinkDescriptor {
            name: "transfer".to_string(),
            kind: SinkKind::TransferAmount,
            argument: Some(2),
            span: Span::at(3, 4),
        };
        assert_eq!(sink.validate(), Ok(()));
    }

    #[test]
    fn rejects_invalid_descriptor_values() {
        let mut source = descriptor("", 1, 1);
        assert_eq!(source.validate(), Err(DescriptorError::EmptyName));
        source = descriptor("   ", 1, 1);
        assert_eq!(source.validate(), Err(DescriptorError::EmptyName));
        source = descriptor("amount\u{7}", 1, 1);
        assert_eq!(source.validate(), Err(DescriptorError::InvalidName));
        source = descriptor(&"a".repeat(MAX_NAME_LEN + 1), 1, 1);
        assert_eq!(source.validate(), Err(DescriptorError::NameTooLong));
        source = descriptor("amount", 0, 1);
        assert_eq!(source.validate(), Err(DescriptorError::InvalidSpan));
        source = descriptor("amount", 4, 2);
        source.span.end_line = 3;
        assert_eq!(source.validate(), Err(DescriptorError::InvalidSpan));

        let sink = SinkDescriptor {
            name: "transfer".to_string(),
            kind: SinkKind::TransferAmount,
            argument: Some(MAX_SOURCES + 1),
            span: Span::at(1, 1),
        };
        assert_eq!(sink.validate(), Err(DescriptorError::InvalidArgument));
    }

    #[test]
    fn registry_is_bounded_deterministic_and_data_only() {
        let mut registry = DescriptorRegistry::default();
        registry
            .register_source(descriptor("late", 9, 1))
            .expect("valid source");
        registry
            .register_source(descriptor("early", 2, 1))
            .expect("valid source");
        registry
            .register_source(descriptor("early", 2, 1))
            .expect("duplicate is ignored");
        let names: Vec<_> = registry
            .sources()
            .iter()
            .map(|source| source.name.as_str())
            .collect();
        assert_eq!(names, vec!["early", "late"]);

        for index in 0..MAX_SOURCES {
            let _ = registry.register_source(descriptor(&format!("s{index}"), index + 1, 1));
        }
        assert_eq!(
            registry.register_source(descriptor("overflow", 1, 1)),
            Err(DescriptorError::SourceLimit)
        );
    }

    #[test]
    fn tracks_direct_parameter_into_auth_subject() {
        let (auth, amounts) = entry_flags(
            r#"
            use soroban_sdk::{contractimpl, Address, Env};

            #[contractimpl]
            impl C {
                pub fn move_funds(env: Env, owner: Address) {
                    owner.require_auth();
                    env.storage().persistent().set(&0, &1);
                }
            }
            "#,
        );
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].sink.kind, SinkKind::AuthSubject);
        assert_eq!(auth[0].path.source_name(), Some("owner"));
        assert!(amounts.is_empty());
    }

    #[test]
    fn tracks_helper_flow_into_auth_subject() {
        let (auth, _) = entry_flags(
            r#"
            use soroban_sdk::{contractimpl, Address, Env};

            #[contractimpl]
            impl C {
                pub fn move_funds(env: Env, owner: Address) {
                    Self::authorize(env, owner);
                }
                fn authorize(env: Env, subject: Address) {
                    subject.require_auth();
                }
            }
            "#,
        );
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0].path.source_name(), Some("owner"));
        assert!(auth[0].path.description().contains("authorize::subject"));
    }

    #[test]
    fn stops_auth_taint_at_documented_sanitizer() {
        let (auth, _) = entry_flags(
            r#"
            use soroban_sdk::{contractimpl, Address, Env};

            #[contractimpl]
            impl C {
                pub fn move_funds(env: Env, owner: Address) {
                    let subject = validate_address(&env, owner);
                    subject.require_auth();
                }
            }
            "#,
        );
        assert!(auth.is_empty());
    }

    #[test]
    fn tracks_direct_arithmetic_and_validated_amounts() {
        let (_, direct) = entry_flags(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn payout(env: Env, token_id: Address, amount: i128) {
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &token_id, &amount);
                }
            }
            "#,
        );
        assert_eq!(direct.len(), 1);
        assert_eq!(direct[0].path.source_name(), Some("amount"));
        assert_eq!(direct[0].sink.kind, SinkKind::TransferAmount);
        assert_eq!(direct[0].sink.argument, Some(2));

        let (_, arithmetic) = entry_flags(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn payout(env: Env, token_id: Address, amount: i128) {
                    let fee = amount - 1;
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &token_id, &fee);
                }
            }
            "#,
        );
        assert_eq!(arithmetic.len(), 1);
        assert_eq!(arithmetic[0].path.source_name(), Some("amount"));
        assert!(arithmetic[0]
            .transformation()
            .is_some_and(|text| text.contains("amount - 1")));

        let (_, validated) = entry_flags(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn payout(env: Env, token_id: Address, amount: i128) {
                    let checked = validate_amount(&env, amount);
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &token_id, &checked);
                }
            }
            "#,
        );
        assert!(validated.is_empty());
    }

    #[test]
    fn records_unknown_when_a_value_has_two_tainted_origins() {
        let (_, amounts) = entry_flags(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn payout(env: Env, token_id: Address, first: i128, second: i128) {
                    let amount = first + second;
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &token_id, &amount);
                }
            }
            "#,
        );
        assert_eq!(amounts.len(), 1);
        assert!(matches!(amounts[0].path, TaintPath::Unknown { .. }));
    }

    #[test]
    fn source_descriptors_cover_parameters_and_decoded_inputs() {
        let (file, index) = entry_of(
            r#"
            use soroban_sdk::{contractimpl, Bytes, Env};

            #[contractimpl]
            impl C {
                pub fn read(env: Env, payload: Bytes) {
                    let decoded = u32::from_xdr(&env, &payload);
                    env.storage().persistent().set(&0, &decoded);
                }
            }
            "#,
        );
        let entries = contract_entry_functions(&file);
        let sources = source_descriptors(&file, &entries[index]);
        assert!(
            sources
                .iter()
                .any(|source| source.name == "payload"
                    && source.kind == SourceKind::FunctionParameter)
        );
        assert!(sources
            .iter()
            .any(|source| source.name == "decoded" && source.kind == SourceKind::DecodedInput));
        assert!(!sources.iter().any(|source| source.name == "env"));
    }
}
