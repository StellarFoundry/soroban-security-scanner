//! Bounded, deterministic program reachability from contract entry points.
//!
//! The per-function CFG answers "can this line be reached from its function
//! entry?" This module answers the complementary question "can this function
//! be reached from a detected contract entry point?" It builds a small,
//! same-file call graph from the parsed syntax tree and never executes,
//! compiles, or guesses control flow.
//!
//! Every gap is recorded as an explicit ambiguity. An ambiguous or incomplete
//! graph never licenses an `Unreachable` verdict: callers must treat the
//! function as still actionable instead of dropping or demoting a real finding
//! on the strength of a partial picture.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Block, Expr};

use super::cfg::{self, ControlFlowGraph, FunctionIndex};
use crate::source::{FunctionSummary, ParsedSource};

/// Maximum number of functions indexed from one parsed source file.
///
/// Past this bound the analysis records `limit_reached` ambiguity and leaves
/// the remaining functions actionable instead of guessing about their callers.
/// The bound is per file so one pathological file cannot suppress context in
/// unrelated files.
pub const MAX_REACHABILITY_FUNCTIONS: usize = 128;
/// Maximum number of call expressions collected from one function body.
pub const MAX_CALLS_PER_FUNCTION: usize = 64;

/// Stable identity of one function in one parsed source file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FunctionKey {
    /// Source path exactly as stored on the parsed source.
    pub file: PathBuf,
    /// 1-based line of the function signature.
    pub line: usize,
    /// 1-based column of the function signature.
    pub column: usize,
    /// Unqualified function name.
    pub name: String,
    /// Name qualified by enclosing module and impl block.
    pub qualified_name: String,
}

impl FunctionKey {
    fn new(source: &ParsedSource, function: &FunctionSummary) -> Self {
        FunctionKey {
            file: source.path.clone(),
            line: function.line,
            column: function.column,
            name: function.name.clone(),
            qualified_name: function.qualified_name.clone(),
        }
    }
}

/// Whether a function can be reached from a detected contract entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FunctionReachability {
    /// Evidence is incomplete; do not claim the function is dead.
    Ambiguous,
    /// The call graph is complete and no path reaches the function.
    Unreachable,
    /// A detected entry point reaches the function.
    Reachable,
}

impl FunctionReachability {
    /// Numeric rank used when combining with line-level reachability.
    pub fn rank(self) -> u8 {
        match self {
            FunctionReachability::Ambiguous => 0,
            FunctionReachability::Unreachable => 1,
            FunctionReachability::Reachable => 2,
        }
    }

    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            FunctionReachability::Ambiguous => "ambiguous",
            FunctionReachability::Unreachable => "unreachable",
            FunctionReachability::Reachable => "reachable",
        }
    }
}

/// Why program reachability could not be proven for every function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AmbiguityKind {
    /// No contract entry point was detected, so there is no trusted root.
    NoEntryPoint,
    /// A source file did not parse and its call graph is unavailable.
    UnparsedSource,
    /// A function body contains a construct the CFG does not model or hit a cap.
    IncompleteCfg,
    /// A call site matched more than one local function; no edge was invented.
    AmbiguousCall,
    /// A call site was not covered by a complete CFG; no edge was invented.
    UncoveredCall,
    /// A function summary could not be matched to a syntax-tree body.
    UnmatchedFunction,
    /// The function or call bound was reached; the remaining work was skipped.
    LimitReached,
}

impl AmbiguityKind {
    /// Stable lowercase label used in diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            AmbiguityKind::NoEntryPoint => "no_entry_point",
            AmbiguityKind::UnparsedSource => "unparsed_source",
            AmbiguityKind::IncompleteCfg => "incomplete_cfg",
            AmbiguityKind::AmbiguousCall => "ambiguous_call",
            AmbiguityKind::UncoveredCall => "uncovered_call",
            AmbiguityKind::UnmatchedFunction => "unmatched_function",
            AmbiguityKind::LimitReached => "limit_reached",
        }
    }
}

/// A deterministic, cached call-graph reachability result for one scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityAnalysis {
    functions: BTreeMap<FunctionKey, FunctionReachability>,
    entry_points: Vec<FunctionKey>,
    spanned: BTreeMap<PathBuf, Vec<(usize, usize, FunctionKey)>>,
    graphs: BTreeMap<FunctionKey, Arc<ControlFlowGraph>>,
    reached_from: BTreeMap<FunctionKey, FunctionKey>,
    ambiguities: BTreeMap<AmbiguityKind, usize>,
}

impl ReachabilityAnalysis {
    /// Builds the analysis from a fixed set of parsed sources.
    ///
    /// Without a detected entry point there is no trusted root, so no function
    /// is claimed unreachable. This also keeps generic Rust projects actionable.
    pub fn new(sources: &[ParsedSource]) -> Self {
        let mut builder = Builder::default();
        builder.collect(sources);
        if builder.entry_points.is_empty() {
            builder.ambiguity(AmbiguityKind::NoEntryPoint);
        }
        builder.finish()
    }

    /// Whether every function's reachability was proven.
    pub fn is_complete(&self) -> bool {
        self.ambiguities.is_empty()
    }

    /// Counts of ambiguity kinds, in stable kind order.
    pub fn ambiguities(&self) -> &BTreeMap<AmbiguityKind, usize> {
        &self.ambiguities
    }

    /// Detected contract entry points, in source and signature order.
    pub fn entry_points(&self) -> &[FunctionKey] {
        &self.entry_points
    }

    /// Reachability of every indexed function.
    pub fn functions(&self) -> &BTreeMap<FunctionKey, FunctionReachability> {
        &self.functions
    }

    /// Reachability of one function, when the function is indexed.
    pub fn reachability_for(&self, key: &FunctionKey) -> Option<FunctionReachability> {
        self.functions.get(key).copied()
    }

    /// Reachability of a function summary in a source file.
    pub fn reachability_for_summary(
        &self,
        source: &ParsedSource,
        function: &FunctionSummary,
    ) -> Option<FunctionReachability> {
        self.reachability_for(&FunctionKey::new(source, function))
    }

    /// The innermost indexed function containing a 1-based line.
    pub fn function_for_line(&self, file: &Path, line: usize) -> Option<&FunctionKey> {
        let spans = self.spanned.get(file)?;
        spans
            .iter()
            .rev()
            .find(|(start, end, _)| *start <= line && line <= *end)
            .map(|(_, _, key)| key)
    }

    /// Reachability of the innermost function containing a line.
    pub fn reachability_for_line(
        &self,
        file: &Path,
        line: usize,
    ) -> Option<(FunctionKey, FunctionReachability)> {
        let key = self.function_for_line(file, line)?.clone();
        let state = self.reachability_for(&key)?;
        Some((key, state))
    }

    /// The cached function CFG, when the function is indexed.
    pub fn cfg_for(&self, key: &FunctionKey) -> Option<Arc<ControlFlowGraph>> {
        self.graphs.get(key).cloned()
    }

    /// The deterministic entry point that reaches a function, when known.
    pub fn entry_point_for(&self, key: &FunctionKey) -> Option<&FunctionKey> {
        self.reached_from.get(key)
    }

    /// Combines function-level and line-level evidence into one verdict.
    ///
    /// A locally reachable line keeps its evidence even when the CFG has gaps.
    /// A locally dead line needs a complete CFG, and a call-graph dead-code
    /// claim needs a complete call graph; ambiguity alone never licenses
    /// `Unreachable`. An ambiguous call graph only omits entry-point attribution
    /// instead of erasing local `Reachable` evidence.
    pub fn line_reachability(
        &self,
        state: FunctionReachability,
        local: cfg::Reachability,
        cfg_complete: bool,
    ) -> cfg::Reachability {
        if local == cfg::Reachability::Unreachable {
            return if cfg_complete {
                cfg::Reachability::Unreachable
            } else {
                cfg::Reachability::Unknown
            };
        }
        if local != cfg::Reachability::Reachable {
            return cfg::Reachability::Unknown;
        }
        if !cfg_complete || state != FunctionReachability::Unreachable {
            return cfg::Reachability::Reachable;
        }
        cfg::Reachability::Unreachable
    }
}

#[derive(Default)]
struct Builder {
    functions: BTreeMap<FunctionKey, FunctionReachability>,
    entry_points: Vec<FunctionKey>,
    spanned: BTreeMap<PathBuf, Vec<(usize, usize, FunctionKey)>>,
    graphs: BTreeMap<FunctionKey, Arc<ControlFlowGraph>>,
    edges: BTreeMap<FunctionKey, BTreeSet<FunctionKey>>,
    local_names: BTreeMap<PathBuf, BTreeMap<String, Vec<FunctionKey>>>,
    infos: Vec<FunctionInfo>,
    ambiguities: BTreeMap<AmbiguityKind, usize>,
}

struct FunctionInfo {
    key: FunctionKey,
    graph: Arc<ControlFlowGraph>,
    calls: Vec<CallSite>,
}

#[derive(Debug)]
struct CallSite {
    line: usize,
    name: String,
    /// Method calls cannot be resolved to a same-file free function.
    is_method: bool,
}

impl Builder {
    fn ambiguity(&mut self, kind: AmbiguityKind) {
        *self.ambiguities.entry(kind).or_insert(0) += 1;
    }

    fn collect(&mut self, sources: &[ParsedSource]) {
        for source in sources {
            let Some(file) = &source.syntax else {
                self.ambiguity(AmbiguityKind::UnparsedSource);
                continue;
            };
            let summaries: BTreeMap<usize, &FunctionSummary> = source
                .functions
                .iter()
                .map(|function| (function.line, function))
                .collect();
            let index = FunctionIndex::new(file);
            let mut indexed_in_file = 0;
            for (block, range) in index.functions() {
                if indexed_in_file >= MAX_REACHABILITY_FUNCTIONS {
                    self.ambiguity(AmbiguityKind::LimitReached);
                    break;
                }
                let Some(function) = summaries.get(&range.0) else {
                    self.ambiguity(AmbiguityKind::UnmatchedFunction);
                    continue;
                };
                let key = FunctionKey::new(source, function);
                if self.functions.contains_key(&key) {
                    self.ambiguity(AmbiguityKind::UnmatchedFunction);
                    continue;
                }

                let graph = Arc::new(cfg::build_function_cfg(block));
                if !graph.is_complete() {
                    self.ambiguity(AmbiguityKind::IncompleteCfg);
                }
                let calls = collect_calls(block);
                if calls.truncated {
                    self.ambiguity(AmbiguityKind::LimitReached);
                }

                self.functions
                    .insert(key.clone(), FunctionReachability::Unreachable);
                indexed_in_file += 1;
                self.graphs.insert(key.clone(), Arc::clone(&graph));
                self.spanned.entry(source.path.clone()).or_default().push((
                    range.0,
                    function.end_line.max(range.1),
                    key.clone(),
                ));
                self.local_names
                    .entry(source.path.clone())
                    .or_default()
                    .entry(function.name.clone())
                    .or_default()
                    .push(key.clone());
                if function.is_contract_entry_point {
                    self.entry_points.push(key.clone());
                }
                self.infos.push(FunctionInfo {
                    key,
                    graph,
                    calls: calls.sites,
                });
            }
        }
        self.entry_points.sort();
        self.entry_points.dedup();
        self.connect_calls();
    }

    fn connect_calls(&mut self) {
        let names = self.local_names.clone();
        let mut extra_ambiguities = Vec::new();
        for info in &self.infos {
            if !info.graph.is_complete() {
                // A macro or cap may hide another call in this body. Do not
                // invent an edge from an incomplete graph.
                continue;
            }
            let Some(candidates_by_name) = names.get(&info.key.file) else {
                continue;
            };
            for call in &info.calls {
                let Some(candidates) = candidates_by_name.get(&call.name) else {
                    // No local function with this name: an external call, not
                    // evidence about a helper in this file.
                    continue;
                };
                if call.is_method {
                    // A method could target an impl in this file, but the
                    // receiver type is not resolved. Record the gap instead of
                    // inventing an edge or declaring the helper dead.
                    extra_ambiguities.push(AmbiguityKind::AmbiguousCall);
                    continue;
                }
                if candidates.len() != 1 {
                    extra_ambiguities.push(AmbiguityKind::AmbiguousCall);
                    continue;
                }
                if info.graph.reachability_at(call.line) != cfg::Reachability::Reachable {
                    // A line the complete CFG does not cover cannot establish
                    // an edge. This is a coverage gap, not a dead call.
                    extra_ambiguities.push(AmbiguityKind::UncoveredCall);
                    continue;
                }
                self.edges
                    .entry(info.key.clone())
                    .or_default()
                    .insert(candidates[0].clone());
            }
        }
        for kind in extra_ambiguities {
            self.ambiguity(kind);
        }
    }

    fn finish(self) -> ReachabilityAnalysis {
        let mut reached_from = BTreeMap::new();
        let mut queue = VecDeque::new();
        for entry in &self.entry_points {
            if self
                .functions
                .get(entry)
                .is_some_and(|state| *state != FunctionReachability::Reachable)
            {
                reached_from.insert(entry.clone(), entry.clone());
                queue.push_back(entry.clone());
            }
        }
        while let Some(current) = queue.pop_front() {
            let Some(nexts) = self.edges.get(&current) else {
                continue;
            };
            for next in nexts {
                if reached_from.contains_key(next) {
                    continue;
                }
                reached_from.insert(next.clone(), reached_from[&current].clone());
                queue.push_back(next.clone());
            }
        }

        let ambiguous = !self.ambiguities.is_empty();
        let functions = self
            .functions
            .into_keys()
            .map(|key| {
                let state = reached_from
                    .get(&key)
                    .map(|_| FunctionReachability::Reachable)
                    .unwrap_or(if ambiguous {
                        FunctionReachability::Ambiguous
                    } else {
                        FunctionReachability::Unreachable
                    });
                (key, state)
            })
            .collect();

        ReachabilityAnalysis {
            functions,
            entry_points: self.entry_points,
            spanned: self.spanned,
            graphs: self.graphs,
            reached_from,
            ambiguities: self.ambiguities,
        }
    }
}

#[derive(Default)]
struct CallCollection {
    sites: Vec<CallSite>,
    truncated: bool,
}

fn collect_calls(block: &Block) -> CallCollection {
    let mut visitor = CallVisitor::default();
    visitor.visit_block(block);
    CallCollection {
        sites: visitor.sites,
        truncated: visitor.truncated,
    }
}

#[derive(Default)]
struct CallVisitor {
    sites: Vec<CallSite>,
    truncated: bool,
}

impl CallVisitor {
    fn push(&mut self, name: String, node: &impl Spanned, is_method: bool) {
        if self.sites.len() >= MAX_CALLS_PER_FUNCTION {
            self.truncated = true;
            return;
        }
        self.sites.push(CallSite {
            line: node.span().start().line,
            name,
            is_method,
        });
    }
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Some(name) = path_name(&node.func) {
            self.push(name, node, false);
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.push(node.method.to_string(), node, true);
        visit::visit_expr_method_call(self, node);
    }
}

fn path_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::parse_source;
    use std::path::Path;

    fn parsed(source: &str) -> Vec<ParsedSource> {
        vec![parse_source(
            Path::new("src/lib.rs"),
            Path::new("."),
            source,
        )]
    }

    fn state(analysis: &ReachabilityAnalysis, name: &str) -> FunctionReachability {
        analysis
            .functions()
            .iter()
            .find(|(key, _)| key.name == name)
            .map(|(_, state)| *state)
            .unwrap_or_else(|| {
                panic!(
                    "function {name} must be indexed: {:#?}",
                    analysis.functions()
                )
            })
    }

    #[test]
    fn helper_only_function_is_unreachable_from_entry_point() {
        let sources = parsed(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set(env: Env, value: u32) {
                    let _ = (env, value);
                }
            }
            fn unused(value: u32) {
                let _ = value;
            }
            "#,
        );
        let analysis = ReachabilityAnalysis::new(&sources);
        assert!(analysis.is_complete(), "{:?}", analysis.ambiguities());
        assert_eq!(state(&analysis, "set"), FunctionReachability::Reachable);
        assert_eq!(
            state(&analysis, "unused"),
            FunctionReachability::Unreachable
        );
    }

    #[test]
    fn helper_called_from_entry_point_is_reachable() {
        let sources = parsed(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set(value: u32) {
                    store(value);
                }
            }
            fn store(value: u32) {
                let _ = value;
            }
            "#,
        );
        let analysis = ReachabilityAnalysis::new(&sources);
        assert!(analysis.is_complete(), "{:?}", analysis.ambiguities());
        let helper = analysis
            .functions()
            .keys()
            .find(|key| key.name == "store")
            .expect("helper key");
        assert_eq!(state(&analysis, "store"), FunctionReachability::Reachable);
        assert_eq!(
            analysis
                .entry_point_for(helper)
                .expect("reached from an entry point")
                .name,
            "set"
        );
    }

    #[test]
    fn incomplete_cfg_marks_ambiguity_instead_of_unreachable() {
        let sources = parsed(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set() {
                    let _ = 1;
                }
            }
            fn unused() {
                unknown_macro!();
            }
            "#,
        );
        let analysis = ReachabilityAnalysis::new(&sources);
        assert!(!analysis.is_complete());
        assert!(analysis
            .ambiguities()
            .contains_key(&AmbiguityKind::IncompleteCfg));
        assert_eq!(state(&analysis, "unused"), FunctionReachability::Ambiguous);
        assert_eq!(
            analysis.line_reachability(
                FunctionReachability::Ambiguous,
                cfg::Reachability::Reachable,
                false
            ),
            cfg::Reachability::Reachable,
            "local reachability is evidence even when the CFG has gaps"
        );
        assert_eq!(
            analysis.line_reachability(
                FunctionReachability::Ambiguous,
                cfg::Reachability::Unreachable,
                false
            ),
            cfg::Reachability::Unknown,
            "an incomplete CFG must not prove dead code"
        );
        assert_eq!(
            analysis.line_reachability(
                FunctionReachability::Ambiguous,
                cfg::Reachability::Reachable,
                true
            ),
            cfg::Reachability::Reachable,
            "call-graph ambiguity must not erase locally proven reachability"
        );
        assert_eq!(
            analysis.line_reachability(
                FunctionReachability::Ambiguous,
                cfg::Reachability::Unreachable,
                true
            ),
            cfg::Reachability::Unreachable,
            "a complete local CFG can prove dead code independently of the call graph"
        );
    }

    #[test]
    fn ambiguous_call_does_not_invent_an_edge() {
        let sources = parsed(
            r#"
            #[contractimpl]
            impl Vault {
                pub fn set() {
                    helper();
                }
            }
            mod a { fn helper() {} }
            mod b { fn helper() {} }
            "#,
        );
        let analysis = ReachabilityAnalysis::new(&sources);
        assert!(
            analysis
                .ambiguities()
                .contains_key(&AmbiguityKind::AmbiguousCall),
            "{:?}",
            analysis.ambiguities()
        );
        let helpers: Vec<_> = analysis
            .functions()
            .iter()
            .filter(|(key, _)| key.name == "helper")
            .collect();
        assert_eq!(helpers.len(), 2);
        assert!(helpers
            .iter()
            .all(|(_, state)| **state == FunctionReachability::Ambiguous));
    }

    #[test]
    fn missing_entry_point_keeps_functions_actionable() {
        let sources = parsed("fn helper() { let _ = 1; }");
        let analysis = ReachabilityAnalysis::new(&sources);
        assert!(analysis
            .ambiguities()
            .contains_key(&AmbiguityKind::NoEntryPoint));
        assert_eq!(state(&analysis, "helper"), FunctionReachability::Ambiguous);
    }

    #[test]
    fn function_limit_is_per_file() {
        let source: String = (0..=MAX_REACHABILITY_FUNCTIONS)
            .map(|index| format!("fn f{index}() {{ let _ = {index}; }}\n"))
            .collect();
        let sources = vec![
            parse_source(Path::new("a.rs"), Path::new("."), &source),
            parse_source(Path::new("b.rs"), Path::new("."), &source),
        ];
        let analysis = ReachabilityAnalysis::new(&sources);

        assert_eq!(
            analysis.ambiguities()[&AmbiguityKind::LimitReached],
            2,
            "each file must report its own bound independently"
        );
        for file in ["a.rs", "b.rs"] {
            let indexed = analysis
                .functions()
                .keys()
                .filter(|key| key.file == *file)
                .count();
            assert_eq!(indexed, MAX_REACHABILITY_FUNCTIONS);
        }
    }

    #[test]
    fn analysis_is_deterministic() {
        let source = r#"
            #[contractimpl]
            impl Vault {
                pub fn set(value: u32) { store(value); }
            }
            fn store(value: u32) { let _ = value; }
            fn unused() {}
        "#;
        let first = ReachabilityAnalysis::new(&parsed(source));
        let second = ReachabilityAnalysis::new(&parsed(source));
        assert_eq!(first, second);
    }
}
