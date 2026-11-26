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
use std::path::Path;

use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::model::{Diagnostic, DiagnosticCode};
use crate::rules::util::{contract_entry_functions, ContractFn};
use crate::source::ParsedSource;

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
/// Maximum number of aggregated taint diagnostics emitted per source file.
pub const MAX_TAINT_DIAGNOSTICS: usize = 8;

/// Why a taint flow could not be established or may be incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaintLimitKind {
    /// A call with tainted arguments targets a function the file does not define.
    UnresolvedCall,
    /// A tainted value reached a construct the propagation pass does not model.
    UnsupportedSyntax,
    /// A configured bound was reached, so some flows were not explored.
    Truncated,
}

impl TaintLimitKind {
    /// Stable lowercase label used in documentation and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            TaintLimitKind::UnresolvedCall => "unresolved_call",
            TaintLimitKind::UnsupportedSyntax => "unsupported_syntax",
            TaintLimitKind::Truncated => "truncated",
        }
    }
}

/// One recorded limit encountered while analyzing taint flows.
///
/// The record deliberately carries only the sink kind and a fixed construct
/// label. It never stores a rendered expression, argument, or literal, so a
/// diagnostic built from it cannot leak source text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintLimit {
    /// What limit was hit.
    pub kind: TaintLimitKind,
    /// Which sink analysis recorded it.
    pub sink: SinkKind,
    /// Fixed label such as `match expression` or `undefined helper`.
    pub construct: &'static str,
    /// Where the limit was observed.
    pub span: Span,
}

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
    /// An address argument of a documented privileged token call.
    PrivilegedAddress,
}

impl SinkKind {
    /// Stable lowercase name used in documentation and tests.
    pub fn as_str(self) -> &'static str {
        match self {
            SinkKind::AuthSubject => "auth_subject",
            SinkKind::TransferAmount => "transfer_amount",
            SinkKind::PrivilegedAddress => "privileged_address",
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

/// An address argument of a privileged token call with caller-controlled
/// provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressFlow {
    /// The privileged call sink.
    pub sink: SinkDescriptor,
    /// How user-controlled data reached the address argument.
    pub path: TaintPath,
}

/// Maximum number of entries in a sanitizer registry.
pub const MAX_SANITIZERS: usize = 64;

/// Maximum length of a registered sanitizer name.
pub const MAX_SANITIZER_NAME_LEN: usize = 64;

/// The taint category a sanitizer is allowed to clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SanitizerKind {
    /// Authorization subjects (`require_auth` receivers).
    AuthSubject,
    /// Token transfer amounts.
    TransferAmount,
    /// Address arguments of privileged token calls.
    PrivilegedAddress,
}

/// How a registered sanitizer is allowed to appear in source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SanitizerForm {
    /// A recognized call whose return value is untainted.
    Call,
    /// A recognized predicate in an early-exit `if !predicate(..) { return; }`.
    Guard,
}

/// One bounded, data-only sanitizer entry and the assumption it encodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sanitizer {
    /// Stable method or free-function name.
    pub name: &'static str,
    /// The only taint category this entry may clear.
    pub kind: SanitizerKind,
    /// The only source form in which this entry is recognized.
    pub form: SanitizerForm,
    /// Why clearing taint is justified; never inferred from a comment.
    pub assumption: &'static str,
}

/// Errors raised while validating a [`SanitizerRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SanitizerError {
    #[error("sanitizer registry exceeds the {MAX_SANITIZERS}-entry limit")]
    TooMany,
    #[error("sanitizer name must be 1..={MAX_SANITIZER_NAME_LEN} printable ASCII characters")]
    InvalidName,
    #[error("sanitizer assumption must not be empty")]
    EmptyAssumption,
    #[error("duplicate sanitizer `{name}` for kind {kind:?}")]
    Duplicate {
        name: &'static str,
        kind: SanitizerKind,
    },
}

/// A bounded registry of sanitizers the analysis is allowed to recognize.
///
/// Only names present with the matching [`SanitizerKind`] and
/// [`SanitizerForm`] clear taint. Unknown helpers, comments, and bare
/// comparisons are never registered, so they cannot suppress a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitizerRegistry {
    entries: &'static [Sanitizer],
}

impl SanitizerRegistry {
    /// Builds a registry from a static slice. Call [`Self::validate`] before
    /// relying on it; the built-in registry is validated by unit tests.
    pub const fn from_static(entries: &'static [Sanitizer]) -> Self {
        Self { entries }
    }

    /// All registered entries, in declaration order.
    pub fn entries(&self) -> &'static [Sanitizer] {
        self.entries
    }

    /// Checks size, names, assumptions, and uniqueness.
    pub fn validate(&self) -> Result<(), SanitizerError> {
        if self.entries.len() > MAX_SANITIZERS {
            return Err(SanitizerError::TooMany);
        }
        let mut seen = BTreeSet::new();
        for entry in self.entries {
            if entry.name.is_empty()
                || entry.name.len() > MAX_SANITIZER_NAME_LEN
                || !entry.name.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(SanitizerError::InvalidName);
            }
            if entry.assumption.trim().is_empty() {
                return Err(SanitizerError::EmptyAssumption);
            }
            if !seen.insert((entry.name, entry.kind, entry.form)) {
                return Err(SanitizerError::Duplicate {
                    name: entry.name,
                    kind: entry.kind,
                });
            }
        }
        Ok(())
    }

    fn contains(&self, name: &str, kind: SanitizerKind, form: SanitizerForm) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.name == name && entry.kind == kind && entry.form == form)
    }
}

const ADDRESS_CALL_ASSUMPTION: &str = "Assumes the named helper explicitly validates or normalizes address provenance; the scanner does not inspect the helper body.";
const AMOUNT_CALL_ASSUMPTION: &str = "Assumes the named helper returns a checked, converted, or clamped amount; the scanner does not inspect the helper body.";
const GUARD_ASSUMPTION: &str = "Assumes the predicate is total and true only for acceptable values, and that invalid values take the modeled early-return branch.";

/// The authoritative sanitizer registry used by all taint flow APIs.
pub const SANITIZER_REGISTRY: SanitizerRegistry = SanitizerRegistry::from_static(&[
    Sanitizer {
        name: "validate_address",
        kind: SanitizerKind::AuthSubject,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "normalize_address",
        kind: SanitizerKind::AuthSubject,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_address",
        kind: SanitizerKind::AuthSubject,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "verified_address",
        kind: SanitizerKind::AuthSubject,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "sanitize_address",
        kind: SanitizerKind::AuthSubject,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "validate_address",
        kind: SanitizerKind::PrivilegedAddress,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "normalize_address",
        kind: SanitizerKind::PrivilegedAddress,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_address",
        kind: SanitizerKind::PrivilegedAddress,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "verified_address",
        kind: SanitizerKind::PrivilegedAddress,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "sanitize_address",
        kind: SanitizerKind::PrivilegedAddress,
        form: SanitizerForm::Call,
        assumption: ADDRESS_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_add",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_sub",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_mul",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_div",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_neg",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "try_from",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "try_into",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "clamp",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "min",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "max",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "validate_amount",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "checked_amount",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "verified_amount",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Call,
        assumption: AMOUNT_CALL_ASSUMPTION,
    },
    Sanitizer {
        name: "is_valid_address",
        kind: SanitizerKind::AuthSubject,
        form: SanitizerForm::Guard,
        assumption: GUARD_ASSUMPTION,
    },
    Sanitizer {
        name: "is_valid_address",
        kind: SanitizerKind::PrivilegedAddress,
        form: SanitizerForm::Guard,
        assumption: GUARD_ASSUMPTION,
    },
    Sanitizer {
        name: "is_valid_amount",
        kind: SanitizerKind::TransferAmount,
        form: SanitizerForm::Guard,
        assumption: GUARD_ASSUMPTION,
    },
]);

/// Method/function names treated as documented sanitizers for authorization
/// subjects.
pub const AUTH_SANITIZERS: &[&str] = &[
    "validate_address",
    "normalize_address",
    "checked_address",
    "verified_address",
    "sanitize_address",
];

/// Address validation helpers are the same documented names as authorization
/// sanitizers: both reason about address provenance, not a Rust type.
pub const ADDRESS_SANITIZERS: &[&str] = AUTH_SANITIZERS;

/// Privileged token calls and the zero-based positions of their address
/// arguments.
///
/// Names come from the documented Stellar token interface. The analysis has no
/// type information, so an unrelated method with the same name can produce a
/// flow; the sink descriptor records the span so a consumer can decide.
const PRIVILEGED_ADDRESS_CALLS: &[(&str, &[usize])] = &[
    ("transfer", &[1]),
    ("transfer_from", &[1, 2]),
    ("approve", &[1]),
    ("mint", &[0]),
    ("burn", &[0]),
    ("burn_from", &[1]),
    ("clawback", &[0]),
];

fn address_argument_indices(name: &str) -> Option<&'static [usize]> {
    PRIVILEGED_ADDRESS_CALLS
        .iter()
        .find(|(method, _)| *method == name)
        .map(|(_, indices)| *indices)
}

/// Whether `name` is a documented privileged address call sink.
///
/// Rule authors can use this to skip expensive flow analysis for entry points
/// that contain no such call.
pub fn is_privileged_address_call(name: &str) -> bool {
    address_argument_indices(name).is_some()
}

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

pub(crate) fn span_of<T: Spanned>(node: &T) -> Span {
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

const EMPTY_SANITIZER_REGISTRY: SanitizerRegistry = SanitizerRegistry::from_static(&[]);

#[derive(Debug, Clone, Copy)]
struct SanitizerContext {
    registry: &'static SanitizerRegistry,
    kind: SanitizerKind,
}

impl SanitizerContext {
    fn for_sink(kind: SinkKind) -> Self {
        Self {
            registry: &SANITIZER_REGISTRY,
            kind: sanitizer_kind(kind),
        }
    }

    fn none() -> Self {
        Self {
            registry: &EMPTY_SANITIZER_REGISTRY,
            kind: SanitizerKind::AuthSubject,
        }
    }

    fn is_call(&self, name: &str) -> bool {
        self.registry.contains(name, self.kind, SanitizerForm::Call)
    }

    fn is_guard(&self, name: &str) -> bool {
        self.registry
            .contains(name, self.kind, SanitizerForm::Guard)
    }

    /// Recognizes only `if !guard(..) { early-exit }` forms. A comment, a bare
    /// comparison, or an unregistered predicate never reaches this method.
    fn guard_binding(
        &self,
        condition: &syn::Expr,
        tainted: &BTreeMap<String, TaintPath>,
    ) -> Option<String> {
        let inner = negated_condition(condition)?;
        guard_call_binding(*self, inner, tainted)
    }
}

fn sanitizer_kind(kind: SinkKind) -> SanitizerKind {
    match kind {
        SinkKind::AuthSubject => SanitizerKind::AuthSubject,
        SinkKind::TransferAmount => SanitizerKind::TransferAmount,
        SinkKind::PrivilegedAddress => SanitizerKind::PrivilegedAddress,
    }
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

fn negated_condition(expr: &syn::Expr) -> Option<&syn::Expr> {
    match expr {
        syn::Expr::Unary(unary) if matches!(unary.op, syn::UnOp::Not(_)) => Some(&unary.expr),
        syn::Expr::Paren(inner) => negated_condition(&inner.expr),
        syn::Expr::Group(inner) => negated_condition(&inner.expr),
        _ => None,
    }
}

fn tainted_path_name(expr: &syn::Expr, tainted: &BTreeMap<String, TaintPath>) -> Option<String> {
    match expr {
        syn::Expr::Reference(inner) => tainted_path_name(&inner.expr, tainted),
        syn::Expr::Paren(inner) => tainted_path_name(&inner.expr, tainted),
        syn::Expr::Group(inner) => tainted_path_name(&inner.expr, tainted),
        _ => path_name(expr)
            .map(|ident| ident.to_string())
            .filter(|name| tainted.contains_key(name)),
    }
}

fn guard_call_binding(
    ctx: SanitizerContext,
    expr: &syn::Expr,
    tainted: &BTreeMap<String, TaintPath>,
) -> Option<String> {
    match expr {
        syn::Expr::Call(call) => {
            let name = callee_name(&call.func)?;
            if !ctx.is_guard(&name) {
                return None;
            }
            call.args
                .iter()
                .find_map(|arg| tainted_path_name(arg, tainted))
        }
        syn::Expr::MethodCall(call) => {
            let name = call.method.to_string();
            if !ctx.is_guard(&name) {
                return None;
            }
            tainted_path_name(&call.receiver, tainted).or_else(|| {
                call.args
                    .iter()
                    .find_map(|arg| tainted_path_name(arg, tainted))
            })
        }
        syn::Expr::Paren(inner) => guard_call_binding(ctx, &inner.expr, tainted),
        syn::Expr::Group(inner) => guard_call_binding(ctx, &inner.expr, tainted),
        _ => None,
    }
}

fn has_early_exit(block: &syn::Block) -> bool {
    struct EarlyExit {
        found: bool,
    }

    impl<'ast> Visit<'ast> for EarlyExit {
        fn visit_expr_return(&mut self, _node: &'ast syn::ExprReturn) {
            self.found = true;
        }

        fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
            if node.mac.path.segments.last().is_some_and(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "panic" | "unreachable" | "abort"
                )
            }) {
                self.found = true;
            }
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if callee_name(&node.func)
                .is_some_and(|name| matches!(name.as_str(), "panic" | "abort"))
            {
                self.found = true;
            }
            if !self.found {
                visit::visit_expr_call(self, node);
            }
        }

        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
        fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}
        fn visit_item(&mut self, _node: &'ast syn::Item) {}
    }

    let mut visitor = EarlyExit { found: false };
    visitor.visit_block(block);
    visitor.found
}

/// Computes the taint path of an expression against a set of tainted locals.
///
/// `depth` bounds recursive helper-return resolution. Path feasibility is not
/// modelled: a value returned on any modelled path taints the call result.
fn taint_of_expr<'b>(
    expr: &syn::Expr,
    tainted: &BTreeMap<String, TaintPath>,
    ctx: SanitizerContext,
    bodies: &BTreeMap<String, Body<'b>>,
    depth: usize,
) -> Option<TaintPath> {
    match expr {
        syn::Expr::Path(path) => path
            .path
            .get_ident()
            .and_then(|ident| tainted.get(&ident.to_string()).cloned()),
        syn::Expr::Reference(inner) => taint_of_expr(&inner.expr, tainted, ctx, bodies, depth),
        syn::Expr::Paren(inner) => taint_of_expr(&inner.expr, tainted, ctx, bodies, depth),
        syn::Expr::Group(inner) => taint_of_expr(&inner.expr, tainted, ctx, bodies, depth),
        syn::Expr::Cast(inner) => taint_of_expr(&inner.expr, tainted, ctx, bodies, depth),
        syn::Expr::Try(inner) => taint_of_expr(&inner.expr, tainted, ctx, bodies, depth),
        syn::Expr::Await(inner) => taint_of_expr(&inner.base, tainted, ctx, bodies, depth),
        syn::Expr::Unary(inner) => taint_of_expr(&inner.expr, tainted, ctx, bodies, depth),
        syn::Expr::Field(inner) => taint_of_expr(&inner.base, tainted, ctx, bodies, depth)
            .map(|path| transformed(path, &inner.to_token_stream().to_string())),
        syn::Expr::Index(inner) => taint_of_expr(&inner.expr, tainted, ctx, bodies, depth)
            .map(|path| transformed(path, &inner.to_token_stream().to_string())),
        syn::Expr::Binary(inner) => combine(
            [
                taint_of_expr(&inner.left, tainted, ctx, bodies, depth),
                taint_of_expr(&inner.right, tainted, ctx, bodies, depth),
            ],
            &inner.to_token_stream().to_string(),
        ),
        syn::Expr::MethodCall(call) => {
            let name = call.method.to_string();
            if ctx.is_call(&name) {
                return None;
            }
            let mut paths = vec![taint_of_expr(&call.receiver, tainted, ctx, bodies, depth)];
            paths.extend(
                call.args
                    .iter()
                    .map(|arg| taint_of_expr(arg, tainted, ctx, bodies, depth)),
            );
            combine(paths, &call.to_token_stream().to_string())
        }
        syn::Expr::Call(call) => {
            let name = callee_name(&call.func);
            if name.as_deref().is_some_and(|name| ctx.is_call(name)) {
                return None;
            }
            // A call to a function defined in this file returns whatever that
            // function's return expressions carry, so taint follows the value
            // instead of stopping at the call boundary.
            if let Some(helper) = name.as_deref().and_then(|name| bodies.get(name)) {
                if depth < MAX_HELPER_DEPTH {
                    return helper_return_taint(helper, call, tainted, ctx, bodies, depth + 1);
                }
                let arg_paths = call
                    .args
                    .iter()
                    .map(|arg| taint_of_expr(arg, tainted, ctx, bodies, depth));
                let combined = combine(arg_paths, &call.to_token_stream().to_string());
                return combined.or_else(|| {
                    call.args
                        .iter()
                        .any(|arg| mentions_tainted(arg, tainted))
                        .then(|| TaintPath::unknown("helper return exceeds the analysis depth"))
                });
            }
            let paths: Vec<_> = call
                .args
                .iter()
                .map(|arg| taint_of_expr(arg, tainted, ctx, bodies, depth))
                .collect();
            combine(paths, &call.to_token_stream().to_string())
        }
        _ => None,
    }
}

/// Computes the taint carried by a helper's return value for one call site.
///
/// Every reachable `return` expression and the tail expression are merged. A
/// value whose taint cannot be resolved from the helper body is recorded as
/// [`TaintPath::Unknown`], never as untainted.
fn helper_return_taint(
    helper: &Body<'_>,
    call: &syn::ExprCall,
    caller_tainted: &BTreeMap<String, TaintPath>,
    ctx: SanitizerContext,
    bodies: &BTreeMap<String, Body<'_>>,
    depth: usize,
) -> Option<TaintPath> {
    let call_site = CallSite {
        name: helper.name.clone(),
        args: call.args.iter().collect(),
        span: span_of(call),
        is_method: false,
    };
    let seeds = helper_seeds(helper, &call_site, caller_tainted, ctx, bodies, depth);
    if seeds.is_empty() {
        return None;
    }
    let tainted = propagate(helper.block, &seeds, ctx, bodies, depth);
    let paths = return_expressions(helper.block).into_iter().map(|expr| {
        taint_of_expr(expr, &tainted, ctx, bodies, depth).or_else(|| {
            mentions_tainted(expr, &tainted)
                .then(|| TaintPath::unknown("helper return uses an unmodelled construct"))
        })
    });
    combine(paths, &format!("return of {}", helper.name))
}

/// Collects `return` expressions and the block's tail expression.
///
/// Returns inside nested closures, async blocks, and nested items belong to a
/// different body and are skipped.
fn return_expressions(block: &syn::Block) -> Vec<&syn::Expr> {
    struct ReturnVisitor<'a> {
        returns: Vec<&'a syn::Expr>,
    }

    impl<'ast> Visit<'ast> for ReturnVisitor<'ast> {
        fn visit_expr_return(&mut self, node: &'ast syn::ExprReturn) {
            if let Some(value) = &node.expr {
                self.returns.push(value);
            }
        }

        fn visit_expr_closure(&mut self, _node: &'ast syn::ExprClosure) {}
        fn visit_expr_async(&mut self, _node: &'ast syn::ExprAsync) {}
        fn visit_item(&mut self, _node: &'ast syn::Item) {}
    }

    let mut visitor = ReturnVisitor {
        returns: Vec::new(),
    };
    visitor.visit_block(block);
    if let Some(syn::Stmt::Expr(expr, None)) = block.stmts.last() {
        if !matches!(expr, syn::Expr::Return(_)) {
            visitor.returns.push(expr);
        }
    }
    visitor.returns
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

struct PropagationVisitor<'a, 'b> {
    tainted: &'a mut BTreeMap<String, TaintPath>,
    ctx: SanitizerContext,
    bodies: &'a BTreeMap<String, Body<'b>>,
    depth: usize,
    conditional_depth: usize,
}

impl PropagationVisitor<'_, '_> {
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
                if self.conditional_depth > 0 && self.tainted.contains_key(name) {
                    // Path-insensitive propagation cannot prove that a
                    // conditional assignment cleared the value. Record the
                    // ambiguity instead of silently dropping the taint.
                    self.tainted.insert(
                        name.to_string(),
                        TaintPath::unknown("conditionally reassigned to an untainted value"),
                    );
                } else {
                    self.tainted.remove(name);
                }
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

/// Tracks nesting inside a conditional construct.
///
/// The propagation pass is not path-sensitive: it visits every branch once.
/// The depth lets an assignment that appears to clear taint inside a branch be
/// recorded as [`TaintPath::Unknown`] instead of assuming the branch always ran.
macro_rules! visit_conditional {
    ($name:ident, $node:ty) => {
        fn $name(&mut self, node: &'ast $node) {
            self.conditional_depth += 1;
            visit::$name(self, node);
            self.conditional_depth -= 1;
        }
    };
}

impl<'ast> Visit<'ast> for PropagationVisitor<'_, '_> {
    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        let guarded = self.ctx.guard_binding(&node.cond, self.tainted);
        if has_early_exit(&node.then_branch) {
            if let Some(name) = guarded {
                self.tainted.remove(&name);
            }
        }
        self.conditional_depth += 1;
        visit::visit_expr_if(self, node);
        self.conditional_depth -= 1;
    }
    visit_conditional!(visit_expr_while, syn::ExprWhile);
    visit_conditional!(visit_expr_for_loop, syn::ExprForLoop);
    visit_conditional!(visit_expr_loop, syn::ExprLoop);
    visit_conditional!(visit_expr_match, syn::ExprMatch);

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if let (syn::Pat::Ident(pattern), Some(init)) = (&node.pat, &node.init) {
            let value = taint_of_expr(&init.expr, self.tainted, self.ctx, self.bodies, self.depth);
            self.assign(&pattern.ident.to_string(), value);
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if let Some(name) = path_name(&node.left) {
            let value = taint_of_expr(&node.right, self.tainted, self.ctx, self.bodies, self.depth);
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
                let value =
                    taint_of_expr(&node.right, self.tainted, self.ctx, self.bodies, self.depth)
                        .or_else(|| {
                            taint_of_expr(
                                &node.left,
                                self.tainted,
                                self.ctx,
                                self.bodies,
                                self.depth,
                            )
                        })
                        .map(|path| transformed(path, &node.to_token_stream().to_string()));
                self.assign(&name.to_string(), value);
            }
        }
        visit::visit_expr_binary(self, node);
    }
}

/// Propagates taint through local bindings and assignments until stable.
fn propagate<'b>(
    block: &syn::Block,
    seeds: &BTreeMap<String, TaintPath>,
    ctx: SanitizerContext,
    bodies: &BTreeMap<String, Body<'b>>,
    depth: usize,
) -> BTreeMap<String, TaintPath> {
    let mut current = seeds.clone();
    for _ in 0..MAX_ITERATIONS {
        let mut next = seeds.clone();
        let mut visitor = PropagationVisitor {
            tainted: &mut next,
            ctx,
            bodies,
            depth,
            conditional_depth: 0,
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

struct SinkVisitor<'a, 'b> {
    tainted: &'a BTreeMap<String, TaintPath>,
    ctx: SanitizerContext,
    bodies: &'a BTreeMap<String, Body<'b>>,
    depth: usize,
    kind: SinkKind,
    flows: Vec<(SinkDescriptor, TaintPath)>,
    limits: Vec<TaintLimit>,
}

impl SinkVisitor<'_, '_> {
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

    /// Resolves a sink argument, recording unsupported syntax when a tainted
    /// value is visible but cannot be followed.
    fn flow_or_limit(&mut self, expr: &syn::Expr) -> Option<TaintPath> {
        let path = taint_of_expr(expr, self.tainted, self.ctx, self.bodies, self.depth);
        if path.is_none() && mentions_tainted(expr, self.tainted) {
            self.limits.push(TaintLimit {
                kind: TaintLimitKind::UnsupportedSyntax,
                sink: self.kind,
                construct: unsupported_construct(expr),
                span: span_of(expr),
            });
        }
        path
    }
}

impl<'ast> Visit<'ast> for SinkVisitor<'_, '_> {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let name = node.method.to_string();
        match self.kind {
            SinkKind::AuthSubject if name == "require_auth" || name == "require_auth_for_args" => {
                if let Some(path) = self.flow_or_limit(&node.receiver) {
                    self.push(&name, None, &node.receiver, path);
                }
            }
            SinkKind::TransferAmount if name == "transfer" || name == "transfer_from" => {
                if let Some(amount) = node.args.last() {
                    if let Some(path) = self.flow_or_limit(amount) {
                        let index = node.args.len().saturating_sub(1);
                        self.push(&name, Some(index), amount, path);
                    }
                }
            }
            SinkKind::PrivilegedAddress => {
                if let Some(indices) = address_argument_indices(&name) {
                    for &index in indices {
                        if let Some(argument) = node.args.get(index) {
                            if let Some(path) = self.flow_or_limit(argument) {
                                self.push(&name, Some(index), argument, path);
                            }
                        }
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
                        if let Some(path) = self.flow_or_limit(subject) {
                            self.push(&name, Some(0), subject, path);
                        }
                    }
                }
                SinkKind::TransferAmount if name == "transfer" => {
                    if let Some(amount) = node.args.last() {
                        if let Some(path) = self.flow_or_limit(amount) {
                            let index = node.args.len().saturating_sub(1);
                            self.push(&name, Some(index), amount, path);
                        }
                    }
                }
                SinkKind::PrivilegedAddress => {
                    if let Some(indices) = address_argument_indices(&name) {
                        for &index in indices {
                            if let Some(argument) = node.args.get(index) {
                                if let Some(path) = self.flow_or_limit(argument) {
                                    self.push(&name, Some(index), argument, path);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        visit::visit_expr_call(self, node);
    }
}

/// Returns true when `expr` mentions a local currently carrying taint.
fn mentions_tainted(expr: &syn::Expr, tainted: &BTreeMap<String, TaintPath>) -> bool {
    struct Mentions<'a> {
        tainted: &'a BTreeMap<String, TaintPath>,
        found: bool,
    }

    impl<'ast> Visit<'ast> for Mentions<'_> {
        fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
            if !self.found {
                if let Some(ident) = node.path.get_ident() {
                    if self.tainted.contains_key(&ident.to_string()) {
                        self.found = true;
                    }
                }
            }
            visit::visit_expr_path(self, node);
        }
    }

    let mut visitor = Mentions {
        tainted,
        found: false,
    };
    visitor.visit_expr(expr);
    visitor.found
}

/// Fixed, source-text-free label for an expression outside the propagation model.
fn unsupported_construct(expr: &syn::Expr) -> &'static str {
    match expr {
        syn::Expr::Reference(inner) => unsupported_construct(&inner.expr),
        syn::Expr::Paren(inner) => unsupported_construct(&inner.expr),
        syn::Expr::Group(inner) => unsupported_construct(&inner.expr),
        syn::Expr::Match(_) => "match expression",
        syn::Expr::Closure(_) => "closure",
        syn::Expr::Async(_) => "async block",
        syn::Expr::Block(_) => "block expression",
        syn::Expr::If(_) => "if expression",
        syn::Expr::Macro(_) => "macro invocation",
        syn::Expr::Struct(_) => "struct expression",
        syn::Expr::Array(_) => "array expression",
        syn::Expr::Tuple(_) => "tuple expression",
        syn::Expr::Let(_) => "let expression",
        _ => "expression",
    }
}

fn sinks_in_body<'b>(
    block: &syn::Block,
    tainted: &BTreeMap<String, TaintPath>,
    kind: SinkKind,
    ctx: SanitizerContext,
    bodies: &BTreeMap<String, Body<'b>>,
    depth: usize,
) -> (Vec<(SinkDescriptor, TaintPath)>, Vec<TaintLimit>) {
    let mut visitor = SinkVisitor {
        tainted,
        ctx,
        bodies,
        depth,
        kind,
        flows: Vec::new(),
        limits: Vec::new(),
    };
    visitor.visit_block(block);
    (visitor.flows, visitor.limits)
}

struct CallSite<'a> {
    name: String,
    args: Vec<&'a syn::Expr>,
    span: Span,
    /// Methods are handled by the sink/sanitizer vocabulary, not as helpers.
    is_method: bool,
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
                    span: span_of(node),
                    is_method: false,
                });
            }
            visit::visit_expr_call(self, node);
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.calls.push(CallSite {
                name: node.method.to_string(),
                args: node.args.iter().collect(),
                span: span_of(node),
                is_method: true,
            });
            visit::visit_expr_method_call(self, node);
        }
    }

    let mut visitor = CallVisitor { calls: Vec::new() };
    visitor.visit_block(block);
    visitor.calls
}

fn helper_seeds<'b>(
    helper: &Body<'_>,
    call: &CallSite<'_>,
    caller_tainted: &BTreeMap<String, TaintPath>,
    ctx: SanitizerContext,
    bodies: &BTreeMap<String, Body<'b>>,
    depth: usize,
) -> BTreeMap<String, TaintPath> {
    let mut seeds = BTreeMap::new();
    if ctx.is_call(&call.name) {
        return seeds;
    }
    for (index, arg) in call.args.iter().enumerate() {
        let Some(param) = helper.params.get(index) else {
            continue;
        };
        if is_env_type(&param.ty) {
            continue;
        }
        if let Some(path) = taint_of_expr(arg, caller_tainted, ctx, bodies, depth) {
            let step = format!("{}::{}", call.name, param.name);
            seeds.insert(param.name.clone(), add_step(path, &step));
        }
    }
    seeds
}

struct Analyzer<'a, 'b> {
    bodies: &'a BTreeMap<String, Body<'b>>,
    kind: SinkKind,
    ctx: SanitizerContext,
    visited: BTreeSet<String>,
    flows: Vec<(SinkDescriptor, TaintPath)>,
    limits: Vec<TaintLimit>,
}

impl<'a, 'b> Analyzer<'a, 'b> {
    fn run(&mut self, body: &Body<'_>, seeds: &BTreeMap<String, TaintPath>, depth: usize) {
        let tainted = propagate(body.block, seeds, self.ctx, self.bodies, depth);
        let (flows, limits) = sinks_in_body(
            body.block,
            &tainted,
            self.kind,
            self.ctx,
            self.bodies,
            depth,
        );
        self.flows.extend(flows);
        self.limits.extend(limits);

        if depth >= MAX_HELPER_DEPTH || self.visited.len() >= MAX_HELPERS {
            if calls_in_body(body.block)
                .iter()
                .any(|call| self.bodies.contains_key(&call.name))
            {
                self.limits.push(TaintLimit {
                    kind: TaintLimitKind::Truncated,
                    sink: self.kind,
                    construct: "helper depth or count bound",
                    span: span_of(body.block),
                });
            }
            return;
        }
        for call in calls_in_body(body.block) {
            if self.ctx.is_call(&call.name) {
                continue;
            }
            let Some(helper) = self.bodies.get(&call.name).cloned() else {
                if !call.is_method
                    && call.name != "new"
                    && call
                        .name
                        .chars()
                        .next()
                        .is_some_and(|first| first.is_ascii_lowercase() || first == '_')
                    && call.args.iter().any(|arg| mentions_tainted(arg, &tainted))
                {
                    self.limits.push(TaintLimit {
                        kind: TaintLimitKind::UnresolvedCall,
                        sink: self.kind,
                        construct: "undefined helper",
                        span: call.span,
                    });
                }
                continue;
            };
            if !self.visited.insert(helper.name.clone()) {
                continue;
            }
            let seeds = helper_seeds(&helper, &call, &tainted, self.ctx, self.bodies, depth);
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

/// Cheap pre-check: the file mentions a call that this sink kind can use.
///
/// Without a matching call anywhere in the file the full propagation pass cannot
/// produce a flow, so skipping it keeps file-wide diagnostics linear instead of
/// quadratic.
fn file_contains_sink(file: &syn::File, kind: SinkKind) -> bool {
    struct SinkPresence {
        kind: SinkKind,
        found: bool,
    }

    impl<'ast> Visit<'ast> for SinkPresence {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            let name = node.method.to_string();
            if matches!(
                self.kind,
                SinkKind::AuthSubject
                    if name == "require_auth" || name == "require_auth_for_args"
            ) || matches!(self.kind, SinkKind::TransferAmount if name == "transfer" || name == "transfer_from")
                || matches!(self.kind, SinkKind::PrivilegedAddress if is_privileged_address_call(&name))
            {
                self.found = true;
            }
            if !self.found {
                visit::visit_expr_method_call(self, node);
            }
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Some(name) = callee_name(&node.func) {
                if matches!(
                    self.kind,
                    SinkKind::AuthSubject
                        if name == "require_auth" || name == "require_auth_for_args"
                ) || matches!(self.kind, SinkKind::TransferAmount if name == "transfer")
                    || matches!(self.kind, SinkKind::PrivilegedAddress if is_privileged_address_call(&name))
                {
                    self.found = true;
                }
            }
            if !self.found {
                visit::visit_expr_call(self, node);
            }
        }
    }

    let mut visitor = SinkPresence { kind, found: false };
    visitor.visit_file(file);
    visitor.found
}

fn analyze_with_limits(
    file: &syn::File,
    entry: &ContractFn<'_>,
    kind: SinkKind,
) -> (Vec<(SinkDescriptor, TaintPath)>, Vec<TaintLimit>) {
    if !file_contains_sink(file, kind) {
        return (Vec::new(), Vec::new());
    }
    let bodies = collect_bodies(file);
    let body = entry_body(&bodies, entry);
    let seeds = seeds_for(&body.params);
    let mut analyzer = Analyzer {
        bodies: &bodies,
        kind,
        ctx: SanitizerContext::for_sink(kind),
        visited: BTreeSet::from([entry.name.clone()]),
        flows: Vec::new(),
        limits: Vec::new(),
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
    let mut limits = analyzer.limits;
    if flows.len() > MAX_FLOWS {
        flows.truncate(MAX_FLOWS);
        limits.push(TaintLimit {
            kind: TaintLimitKind::Truncated,
            sink: kind,
            construct: "flow count bound",
            span: span_of(body.block),
        });
    }
    limits.sort_by(|a, b| {
        (a.span, a.kind, a.sink, a.construct).cmp(&(b.span, b.kind, b.sink, b.construct))
    });
    limits.dedup();
    limits.truncate(MAX_FLOWS);
    (flows, limits)
}

fn analyze(
    file: &syn::File,
    entry: &ContractFn<'_>,
    kind: SinkKind,
) -> Vec<(SinkDescriptor, TaintPath)> {
    analyze_with_limits(file, entry, kind).0
}

/// Limits that explain why a taint flow may be missing or incomplete.
///
/// Bounded by [`MAX_FLOWS`], deterministic, and source-text-free: each record
/// carries a fixed reason label and a span, never a rendered expression.
pub fn taint_limits(file: &syn::File, entry: &ContractFn<'_>, kind: SinkKind) -> Vec<TaintLimit> {
    analyze_with_limits(file, entry, kind).1
}

/// Authorization subjects derived from caller-controlled data in `entry`.
///
/// Values passed through a documented [`AUTH_SANITIZERS`] helper are omitted.
/// Intra-file helpers are followed up to [`MAX_HELPER_DEPTH`].
pub fn auth_subject_flows(file: &syn::File, entry: &ContractFn<'_>) -> Vec<AuthFlow> {
    analyze(file, entry, SinkKind::AuthSubject)
        .into_iter()
        .map(|(sink, path)| AuthFlow { sink, path })
        .collect()
}

/// Token transfer amounts derived from caller-controlled data in `entry`.
///
/// Values passed through a documented [`AMOUNT_SANITIZERS`] helper are omitted.
/// Arithmetic transformations remain visible in [`AmountFlow::transformation`].
pub fn transfer_amount_flows(file: &syn::File, entry: &ContractFn<'_>) -> Vec<AmountFlow> {
    analyze(file, entry, SinkKind::TransferAmount)
        .into_iter()
        .map(|(sink, path)| AmountFlow { sink, path })
        .collect()
}

/// Address arguments of documented privileged token calls derived from
/// caller-controlled data in `entry`.
///
/// Values passed through a documented [`ADDRESS_SANITIZERS`] helper are omitted.
/// The analysis never treats an `Address` type annotation as validation; only a
/// documented helper name clears the flow.
pub fn address_argument_flows(file: &syn::File, entry: &ContractFn<'_>) -> Vec<AddressFlow> {
    analyze(file, entry, SinkKind::PrivilegedAddress)
        .into_iter()
        .map(|(sink, path)| AddressFlow { sink, path })
        .collect()
}

/// Source descriptors visible in `entry`, bounded and in source order.
pub fn source_descriptors(file: &syn::File, entry: &ContractFn<'_>) -> Vec<SourceDescriptor> {
    let bodies = collect_bodies(file);
    let body = entry_body(&bodies, entry);
    let seeds = seeds_for(&body.params);
    let tainted = propagate(body.block, &seeds, SanitizerContext::none(), &bodies, 0);
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

/// Reports why a taint flow may be missing or incomplete for one source file.
///
/// Aggregated by `(reason, sink)` with the first span, bounded to
/// [`MAX_TAINT_DIAGNOSTICS`] diagnostics plus an omitted-count notice. Messages
/// contain counts and fixed labels only: no expression, argument, literal, or
/// other source text can reach the report.
pub fn unresolved_flow_diagnostics(source: &ParsedSource, relative_path: &Path) -> Vec<Diagnostic> {
    let Some(file) = &source.syntax else {
        return Vec::new();
    };
    let mut groups: BTreeMap<(TaintLimitKind, SinkKind, &'static str), (usize, Span)> =
        BTreeMap::new();
    // Presence is a file-level property. Checking it once avoids re-walking the
    // whole file for every entry point.
    let active: Vec<SinkKind> = [
        SinkKind::AuthSubject,
        SinkKind::TransferAmount,
        SinkKind::PrivilegedAddress,
    ]
    .into_iter()
    .filter(|kind| file_contains_sink(file, *kind))
    .collect();
    if active.is_empty() {
        return Vec::new();
    }
    for entry in contract_entry_functions(file) {
        if !entry.is_public {
            continue;
        }
        for kind in &active {
            for limit in taint_limits(file, &entry, *kind) {
                let group = groups
                    .entry((limit.kind, limit.sink, limit.construct))
                    .or_insert((0, limit.span));
                group.0 += 1;
                if limit.span < group.1 {
                    group.1 = limit.span;
                }
            }
        }
    }

    if groups.is_empty() {
        return Vec::new();
    }

    let total = groups.len();
    let limit = if total > MAX_TAINT_DIAGNOSTICS {
        MAX_TAINT_DIAGNOSTICS - 1
    } else {
        MAX_TAINT_DIAGNOSTICS
    };
    let mut entries: Vec<_> = groups.into_iter().collect();
    entries.sort_by(|(a_key, a), (b_key, b)| {
        (a.1, a_key.0, a_key.1, a_key.2).cmp(&(b.1, b_key.0, b_key.1, b_key.2))
    });

    let mut diagnostics = Vec::new();
    for ((kind, sink, construct), (count, span)) in entries.into_iter().take(limit) {
        let message = match kind {
            TaintLimitKind::UnresolvedCall => format!(
                "{count} tainted call(s) to an undefined helper ({construct}) for \
                 `{}` sinks; flows may be incomplete",
                sink.as_str()
            ),
            TaintLimitKind::UnsupportedSyntax => format!(
                "{count} tainted {construct}(s) at `{}` sinks are outside the taint \
                 model; flows may be incomplete",
                sink.as_str()
            ),
            TaintLimitKind::Truncated => format!(
                "taint analysis for `{}` sinks hit {construct}; flows may be truncated",
                sink.as_str()
            ),
        };
        diagnostics.push(
            Diagnostic::warning(
                DiagnosticCode::TaintIncomplete,
                message,
                Some(relative_path.to_path_buf()),
            )
            .with_span(span.line.max(1), span.column.max(1)),
        );
    }
    if total > limit {
        diagnostics.push(
            Diagnostic::info(
                DiagnosticCode::TaintIncomplete,
                format!(
                    "{} additional taint diagnostic group(s) omitted",
                    total - limit
                ),
                Some(relative_path.to_path_buf()),
            )
            .with_span(1, 1),
        );
    }
    diagnostics
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
    fn tracks_direct_decoded_and_validated_addresses() {
        let (file, index) = entry_of(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env, String};

            #[contractimpl]
            impl C {
                pub fn payout(env: Env, token_id: Address, to: Address, raw: String, amount: i128) {
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &to, &amount);
                    let decoded = Address::from_string(&raw);
                    client.transfer(&env.current_contract_address(), &decoded, &amount);
                    let checked = validate_address(&env, to);
                    client.transfer(&env.current_contract_address(), &checked, &amount);
                }
            }
            "#,
        );
        let entries = contract_entry_functions(&file);
        let flows = address_argument_flows(&file, &entries[index]);
        let sources: Vec<_> = flows
            .iter()
            .filter_map(|flow| flow.path.source_name())
            .collect();
        assert!(flows
            .iter()
            .all(|flow| flow.sink.kind == SinkKind::PrivilegedAddress));
        assert!(flows
            .iter()
            .all(|flow| flow.sink.name == "transfer" && flow.sink.argument == Some(1)));
        assert!(sources.contains(&"to"));
        assert!(sources.contains(&"raw"));
        assert!(
            !sources.contains(&"checked"),
            "documented address validation must clear the flow"
        );
    }

    #[test]
    fn address_type_annotation_is_not_validation() {
        let (file, index) = entry_of(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn payout(env: Env, token_id: Address, to: Address, amount: i128) {
                    let _typed: Address = to;
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(&env.current_contract_address(), &to, &amount);
                }
            }
            "#,
        );
        let entries = contract_entry_functions(&file);
        let flows = address_argument_flows(&file, &entries[index]);
        assert_eq!(
            flows.len(),
            1,
            "an `Address` type is not validation: {flows:#?}"
        );
        assert_eq!(flows[0].path.source_name(), Some("to"));
    }

    #[test]
    fn every_privileged_call_reports_its_address_arguments() {
        let (file, index) = entry_of(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn payout(env: Env, token_id: Address, from: Address, to: Address, spender: Address, amount: i128) {
                    let client = token::Client::new(&env, &token_id);
                    client.transfer_from(&spender, &from, &to, &amount);
                    client.approve(&from, &spender, &amount, &1);
                    client.mint(&to, &amount);
                    client.burn(&from, &amount);
                    client.burn_from(&spender, &from, &amount);
                    client.clawback(&from, &amount);
                }
            }
            "#,
        );
        let entries = contract_entry_functions(&file);
        let flows = address_argument_flows(&file, &entries[index]);
        let mut sinks: Vec<_> = flows
            .iter()
            .map(|flow| (flow.sink.name.as_str(), flow.sink.argument))
            .collect();
        sinks.sort_unstable();
        sinks.dedup();
        assert_eq!(
            sinks,
            vec![
                ("approve", Some(1)),
                ("burn", Some(0)),
                ("burn_from", Some(1)),
                ("clawback", Some(0)),
                ("mint", Some(0)),
                ("transfer_from", Some(1)),
                ("transfer_from", Some(2)),
            ]
        );
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

    fn diagnostics_of(source: &str) -> Vec<Diagnostic> {
        let parsed = crate::source::parse_source(
            std::path::Path::new("src/lib.rs"),
            std::path::Path::new("."),
            source,
        );
        unresolved_flow_diagnostics(&parsed, std::path::Path::new("src/lib.rs"))
    }

    #[test]
    fn aggregates_unsupported_taint_syntax() {
        let diagnostics = diagnostics_of(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn pay(env: Env, token_id: Address, amount: i128) {
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(
                        &env.current_contract_address(),
                        &token_id,
                        &(match amount { value => value }),
                    );
                    client.transfer(
                        &env.current_contract_address(),
                        &token_id,
                        &(match amount { value => value }),
                    );
                }
            }
            "#,
        );
        let matching: Vec<_> = diagnostics
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == DiagnosticCode::TaintIncomplete
                    && diagnostic.message.contains("match expression")
            })
            .collect();
        assert_eq!(matching.len(), 1, "got: {diagnostics:#?}");
        assert!(matching[0].message.contains("2 tainted match expression"));
        assert_eq!(matching[0].line, Some(11));
    }

    #[test]
    fn taint_diagnostics_never_include_source_text() {
        let diagnostics = diagnostics_of(
            r#"
            use soroban_sdk::{contractimpl, token, Address, Env};

            #[contractimpl]
            impl C {
                pub fn pay(env: Env, token_id: Address, amount: i128) {
                    let secret_token_abc123 = amount;
                    let client = token::Client::new(&env, &token_id);
                    client.transfer(
                        &env.current_contract_address(),
                        &token_id,
                        &(match secret_token_abc123 { value => value }),
                    );
                }
            }
            "#,
        );
        assert!(!diagnostics.is_empty(), "expected a taint diagnostic");
        for diagnostic in &diagnostics {
            assert!(
                !diagnostic.message.contains("secret_token_abc123"),
                "diagnostic leaked source text: {}",
                diagnostic.message
            );
        }
    }
}
