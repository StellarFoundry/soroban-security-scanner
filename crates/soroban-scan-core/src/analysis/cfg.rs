//! Bounded, deterministic control-flow graphs for function bodies.
//!
//! The graph is built from the parsed syntax tree only: it never executes or
//! compiles the scanned project. Nodes cover supported statements and
//! expressions, and every construct the builder cannot model becomes an
//! explicit [`NodeKind::Unknown`] node instead of an invented edge.
//!
//! Building is capped by [`MAX_CFG_NODES`], [`MAX_CFG_EDGES`], and
//! [`MAX_CFG_DEPTH`]. Node ids follow source order, edges are appended in
//! creation order, and reachability is a deterministic graph search from the
//! entry node, so the same body always produces the same graph.

use syn::spanned::Spanned;
use syn::{Block, Expr, Stmt};

use super::taint::{span_of, Span};

/// Maximum number of nodes in one function graph.
pub const MAX_CFG_NODES: usize = 256;
/// Maximum number of edges in one function graph.
pub const MAX_CFG_EDGES: usize = 512;
/// Maximum nesting depth of control-flow constructs the builder follows.
pub const MAX_CFG_DEPTH: usize = 32;
/// Maximum number of truncation diagnostics a scan reports before summarizing.
///
/// Truncated graphs are also skipped by consumers, so one diagnostic per
/// truncated function is enough to explain the gap; the cap keeps a pathological
/// file from flooding the report.
pub const MAX_CFG_DIAGNOSTICS: usize = 8;

/// What a node represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    /// The single entry node of a function.
    Entry,
    /// The single exit node of a function.
    Exit,
    /// A straight-line statement or expression.
    Statement,
    /// A branch condition (`if`, or a `match` scrutinee).
    Branch,
    /// A loop header (`while`, `for`, or `loop`).
    Loop,
    /// A `match` expression.
    Match,
    /// A `return` expression.
    Return,
    /// A construct the builder deliberately does not model.
    Unknown,
}

/// One node in a control-flow graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CfgNode {
    /// Stable node id, in source traversal order.
    pub id: usize,
    /// What the node represents.
    pub kind: NodeKind,
    /// Source span of the construct.
    pub span: Span,
}

/// A directed edge between two nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CfgEdge {
    /// Source node id.
    pub from: usize,
    /// Target node id.
    pub to: usize,
}

/// A bounded control-flow graph for one function body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFlowGraph {
    /// Nodes in deterministic order.
    pub nodes: Vec<CfgNode>,
    /// Edges in deterministic order.
    pub edges: Vec<CfgEdge>,
    /// Id of the entry node (always `0`).
    pub entry: usize,
    /// Id of the exit node (always `1`).
    pub exit: usize,
    /// True when a cap stopped the builder early.
    pub truncated: bool,
    reachable: Vec<bool>,
}

impl ControlFlowGraph {
    /// Whether a node id can be reached from the entry node.
    pub fn is_reachable(&self, id: usize) -> bool {
        self.reachable.get(id).copied().unwrap_or(false)
    }

    /// Node ids reachable from the entry node, in id order.
    pub fn reachable_nodes(&self) -> impl Iterator<Item = usize> + '_ {
        self.reachable
            .iter()
            .enumerate()
            .filter(|(_, reachable)| **reachable)
            .map(|(id, _)| id)
    }

    /// Reachability of the statement(s) on a 1-based source line.
    ///
    /// A line covered by at least one reachable node is [`Reachability::Reachable`].
    /// When every node covering the line is unreachable the result is
    /// [`Reachability::Unreachable`]. A line the graph does not cover is
    /// [`Reachability::Unknown`], never a guess.
    pub fn reachability_at(&self, line: usize) -> Reachability {
        let mut covered = false;
        for node in &self.nodes {
            if node.span.line <= line && line <= node.span.end_line {
                covered = true;
                if self.is_reachable(node.id) {
                    return Reachability::Reachable;
                }
            }
        }
        if covered {
            Reachability::Unreachable
        } else {
            Reachability::Unknown
        }
    }
}

/// Whether a source line is reachable from a function entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reachability {
    /// The line is not covered by any known graph node.
    #[default]
    Unknown,
    /// The line is covered only by nodes the graph cannot reach.
    Unreachable,
    /// The line is covered by a reachable node.
    Reachable,
}

impl Reachability {
    /// Numeric rank used by the finding ordering key.
    ///
    /// Reachable findings come first, then unknown ones, then findings proven
    /// unreachable. Unknown is ranked below reachable on purpose: it is
    /// actionable until proven otherwise.
    pub fn rank(self) -> u8 {
        match self {
            Reachability::Unreachable => 0,
            Reachability::Unknown => 1,
            Reachability::Reachable => 2,
        }
    }

    /// Stable lowercase name.
    pub fn as_str(self) -> &'static str {
        match self {
            Reachability::Unknown => "unknown",
            Reachability::Unreachable => "unreachable",
            Reachability::Reachable => "reachable",
        }
    }
}

/// Builds the control-flow graph for a function body.
pub fn build_function_cfg(block: &Block) -> ControlFlowGraph {
    Builder::new(block).finish(block)
}

/// An index of the function bodies in one file.
///
/// Spans are computed once so ranking many findings in the same file does not
/// walk the syntax tree once per finding.
pub struct FunctionIndex<'a> {
    entries: Vec<(usize, usize, &'a syn::Block)>,
}

impl<'a> FunctionIndex<'a> {
    /// Builds the index from a parsed file.
    pub fn new(file: &'a syn::File) -> Self {
        fn walk<'a>(items: &'a [syn::Item], out: &mut Vec<(usize, usize, &'a syn::Block)>) {
            for item in items {
                match item {
                    syn::Item::Fn(function) => {
                        out.push((
                            function.sig.span().start().line,
                            function.block.span().end().line,
                            &function.block,
                        ));
                    }
                    syn::Item::Impl(imp) => {
                        for impl_item in &imp.items {
                            if let syn::ImplItem::Fn(function) = impl_item {
                                out.push((
                                    function.sig.span().start().line,
                                    function.block.span().end().line,
                                    &function.block,
                                ));
                            }
                        }
                    }
                    syn::Item::Mod(module) => {
                        if let Some((_, nested)) = &module.content {
                            walk(nested, out);
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut entries = Vec::new();
        walk(&file.items, &mut entries);
        entries.sort_by_key(|(start, _, _)| *start);
        FunctionIndex { entries }
    }

    /// Returns the innermost function body containing a 1-based line.
    pub fn find(&self, line: usize) -> Option<(&'a syn::Block, (usize, usize))> {
        let index = self.entries.partition_point(|(start, _, _)| *start <= line);
        let (start, end, block) = self.entries.get(index.checked_sub(1)?)?;
        (*start <= line && line <= *end).then_some((*block, (*start, *end)))
    }
}

/// Finds the function body containing a 1-based line.
///
/// Prefer [`FunctionIndex`] when looking up several lines in the same file.
pub fn function_for_line(file: &syn::File, line: usize) -> Option<(&syn::Block, (usize, usize))> {
    FunctionIndex::new(file).find(line)
}

struct Builder {
    nodes: Vec<CfgNode>,
    edges: Vec<CfgEdge>,
    truncated: bool,
}

impl Builder {
    fn new(block: &Block) -> Self {
        let start = block.brace_token.span.open().start();
        let end = block.span().end();
        let entry = CfgNode {
            id: 0,
            kind: NodeKind::Entry,
            span: Span::at(start.line, start.column + 1),
        };
        let exit = CfgNode {
            id: 1,
            kind: NodeKind::Exit,
            span: Span::at(end.line, end.column + 1),
        };
        Builder {
            nodes: vec![entry, exit],
            edges: Vec::new(),
            truncated: false,
        }
    }

    fn finish(mut self, block: &Block) -> ControlFlowGraph {
        let exits = self.build_block(block, vec![0], 0);
        for from in exits {
            self.edge(from, 1);
        }
        let reachable = reachable_from(&self.nodes, &self.edges);
        ControlFlowGraph {
            nodes: self.nodes,
            edges: self.edges,
            entry: 0,
            exit: 1,
            truncated: self.truncated,
            reachable,
        }
    }

    fn node(&mut self, kind: NodeKind, span: Span) -> Option<usize> {
        if self.nodes.len() >= MAX_CFG_NODES {
            self.truncated = true;
            return None;
        }
        let id = self.nodes.len();
        self.nodes.push(CfgNode { id, kind, span });
        Some(id)
    }

    fn edge(&mut self, from: usize, to: usize) {
        if from >= self.nodes.len() || to >= self.nodes.len() {
            return;
        }
        if self.edges.len() >= MAX_CFG_EDGES {
            self.truncated = true;
            return;
        }
        let edge = CfgEdge { from, to };
        if !self.edges.contains(&edge) {
            self.edges.push(edge);
        }
    }

    fn simple(
        &mut self,
        kind: NodeKind,
        span: Span,
        incoming: Vec<usize>,
        depth: usize,
    ) -> Vec<usize> {
        let Some(id) = self.node(kind, span) else {
            return incoming;
        };
        for from in incoming {
            self.edge(from, id);
        }
        let _ = depth;
        vec![id]
    }

    fn build_block(&mut self, block: &Block, mut incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        for stmt in &block.stmts {
            incoming = self.build_stmt(stmt, incoming, depth);
        }
        incoming
    }

    fn build_stmt(&mut self, stmt: &Stmt, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        match stmt {
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    if is_control_flow(&init.expr) {
                        return self.build_expr(&init.expr, incoming, depth);
                    }
                }
                self.simple(NodeKind::Statement, span_of(local), incoming, depth)
            }
            Stmt::Expr(expr, _) => self.build_expr(expr, incoming, depth),
            Stmt::Item(item) => self.simple(NodeKind::Unknown, span_of(item), incoming, depth),
            Stmt::Macro(mac) => self.simple(NodeKind::Unknown, span_of(mac), incoming, depth),
        }
    }

    fn build_expr(&mut self, expr: &Expr, incoming: Vec<usize>, depth: usize) -> Vec<usize> {
        if depth >= MAX_CFG_DEPTH {
            return self.simple(NodeKind::Unknown, span_of(expr), incoming, depth);
        }
        match expr {
            Expr::If(node) => {
                // Header spans stay at the construct start so a line inside a
                // branch is decided by that branch's own statements.
                let cond = self.simple(NodeKind::Branch, point_span(expr), incoming, depth);
                let cond = cond.first().copied().unwrap_or(0);
                let mut exits = self.build_block(&node.then_branch, vec![cond], depth + 1);
                match &node.else_branch {
                    Some((_, else_expr)) => {
                        exits.extend(self.build_expr(else_expr, vec![cond], depth + 1));
                    }
                    None => exits.push(cond),
                }
                exits
            }
            Expr::While(node) => {
                self.build_loop(point_span(expr), &node.body, incoming, depth, true)
            }
            Expr::ForLoop(node) => {
                self.build_loop(point_span(expr), &node.body, incoming, depth, true)
            }
            Expr::Loop(node) => {
                self.build_loop(point_span(expr), &node.body, incoming, depth, false)
            }
            Expr::Match(node) => {
                let header = self.simple(NodeKind::Match, point_span(expr), incoming, depth);
                let header = header.first().copied().unwrap_or(0);
                let mut exits = Vec::new();
                for arm in &node.arms {
                    exits.extend(self.build_expr(&arm.body, vec![header], depth + 1));
                }
                if node.arms.is_empty() {
                    exits.push(header);
                }
                exits
            }
            Expr::Block(node) => self.build_block(&node.block, incoming, depth),
            Expr::Unsafe(node) => self.build_block(&node.block, incoming, depth),
            Expr::Return(_) => {
                let exits = self.simple(NodeKind::Return, span_of(expr), incoming, depth);
                for from in &exits {
                    self.edge(*from, 1);
                }
                Vec::new()
            }
            Expr::Break(_) | Expr::Continue(_) => {
                // Break/continue targets are not modelled. The node stays
                // explicit so a reader knows the successor is not the source
                // order default.
                self.simple(NodeKind::Unknown, span_of(expr), incoming, depth)
            }
            Expr::Macro(_) | Expr::Closure(_) | Expr::Async(_) => {
                self.simple(NodeKind::Unknown, span_of(expr), incoming, depth)
            }
            _ => self.simple(NodeKind::Statement, span_of(expr), incoming, depth),
        }
    }

    fn build_loop(
        &mut self,
        span: Span,
        body: &Block,
        incoming: Vec<usize>,
        depth: usize,
        may_exit: bool,
    ) -> Vec<usize> {
        let header = self.simple(NodeKind::Loop, span, incoming, depth);
        let header = header.first().copied().unwrap_or(0);
        let body_exits = self.build_block(body, vec![header], depth + 1);
        for from in &body_exits {
            self.edge(*from, header);
        }
        if may_exit {
            // `while`/`for` can always skip the body.
            return vec![header];
        }
        // A bare `loop` only leaves through `break`, `return`, or a panic.
        // Those targets are not resolved, so the continuation is an explicit
        // Unknown node rather than an invented direct edge from the header.
        match self.node(NodeKind::Unknown, span) {
            Some(unknown) => {
                self.edge(header, unknown);
                vec![unknown]
            }
            None => vec![header],
        }
    }
}

fn point_span<T: Spanned>(node: &T) -> Span {
    let start = node.span().start();
    Span::at(start.line, start.column + 1)
}

fn is_control_flow(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::If(_)
            | Expr::While(_)
            | Expr::ForLoop(_)
            | Expr::Loop(_)
            | Expr::Match(_)
            | Expr::Block(_)
            | Expr::Unsafe(_)
    )
}

fn reachable_from(nodes: &[CfgNode], edges: &[CfgEdge]) -> Vec<bool> {
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for edge in edges {
        if edge.from < nodes.len() && edge.to < nodes.len() {
            adjacency[edge.from].push(edge.to);
        }
    }
    let mut reachable = vec![false; nodes.len()];
    if nodes.is_empty() {
        return reachable;
    }
    let mut stack = vec![0usize];
    while let Some(id) = stack.pop() {
        if reachable[id] {
            continue;
        }
        reachable[id] = true;
        for &next in &adjacency[id] {
            if !reachable[next] {
                stack.push(next);
            }
        }
    }
    reachable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(body: &str) -> ControlFlowGraph {
        let block: Block = syn::parse_str(body).expect("test body must parse");
        build_function_cfg(&block)
    }

    fn kinds(cfg: &ControlFlowGraph) -> Vec<NodeKind> {
        cfg.nodes.iter().map(|node| node.kind).collect()
    }

    #[test]
    fn straight_line_body_has_entry_statement_and_exit() {
        let graph = cfg("{ let amount = 1; transfer(amount); }");
        assert_eq!(
            kinds(&graph),
            vec![
                NodeKind::Entry,
                NodeKind::Exit,
                NodeKind::Statement,
                NodeKind::Statement
            ]
        );
        assert_eq!(graph.nodes.len(), 4);
        assert_eq!(graph.edges.len(), 3);
        assert!(graph.is_reachable(graph.exit));
        assert!(!graph.truncated);
    }

    #[test]
    fn if_else_creates_branch_and_join_through_two_paths() {
        let graph = cfg("{ if ready { first(); } else { second(); } third(); }");
        let branch = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Branch)
            .expect("branch node");
        let outgoing: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.from == branch.id)
            .collect();
        assert_eq!(outgoing.len(), 2, "if/else must fork into two paths");
        assert!(graph
            .nodes
            .iter()
            .filter(|node| node.kind == NodeKind::Statement)
            .all(|node| graph.is_reachable(node.id)));
    }

    #[test]
    fn while_loop_has_a_back_edge_to_the_header() {
        let graph = cfg("{ while more() { step(); } done(); }");
        let header = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Loop)
            .expect("loop header");
        let back_edge = graph
            .edges
            .iter()
            .any(|edge| edge.to == header.id && edge.from != graph.entry);
        assert!(back_edge, "loop body must edge back to its header");
        assert!(graph.is_reachable(graph.exit));
    }

    #[test]
    fn bare_loop_exit_is_explicitly_unknown() {
        let graph = cfg("{\n loop {\n step();\n }\n after();\n}");
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.kind == NodeKind::Unknown));
        let after = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Statement && node.span.line == 5)
            .expect("statement after loop");
        assert!(graph.is_reachable(after.id));
    }

    #[test]
    fn match_arms_all_stay_reachable() {
        let graph = cfg("{ match value { 0 => a(), _ => b(), } }");
        let header = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Match)
            .expect("match node");
        let arms = graph
            .edges
            .iter()
            .filter(|edge| edge.from == header.id)
            .count();
        assert_eq!(arms, 2, "one edge per match arm");
    }

    #[test]
    fn unsupported_constructs_become_unknown_nodes() {
        let graph = cfg("{ unknown_macro!(); break; }");
        assert!(graph
            .nodes
            .iter()
            .any(|node| node.kind == NodeKind::Unknown));
    }

    #[test]
    fn statements_after_return_are_unreachable_not_hidden() {
        let graph = cfg("{\n return;\n cleanup();\n}");
        let cleanup = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Statement)
            .expect("statement after return");
        assert!(!graph.is_reachable(cleanup.id));
        assert_eq!(
            graph.reachability_at(cleanup.span.line),
            Reachability::Unreachable
        );
    }

    #[test]
    fn code_after_return_inside_a_branch_is_unreachable() {
        let graph = cfg("{\n if ready {\n return;\n cleanup();\n }\n done();\n}");
        let cleanup = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Statement && node.span.line == 4)
            .expect("statement after return");
        let done = graph
            .nodes
            .iter()
            .find(|node| node.kind == NodeKind::Statement && node.span.line == 6)
            .expect("statement after the branch");
        assert!(!graph.is_reachable(cleanup.id));
        assert!(graph.is_reachable(done.id));
    }

    #[test]
    fn reachability_unknown_for_lines_outside_the_body() {
        let graph = cfg("{ let value = 1; }");
        assert_eq!(graph.reachability_at(9999), Reachability::Unknown);
    }

    #[test]
    fn node_and_edge_caps_are_enforced() {
        let mut body = String::from("{");
        for index in 0..(MAX_CFG_NODES + 20) {
            body.push_str(&format!(" statement_{index}();"));
        }
        body.push('}');
        let graph = cfg(&body);
        assert!(graph.nodes.len() <= MAX_CFG_NODES);
        assert!(graph.edges.len() <= MAX_CFG_EDGES);
        assert!(graph.truncated);
    }

    #[test]
    fn output_is_deterministic() {
        let body = "{ if a { b(); } while c { d(); } match e { _ => f(), } }";
        let first = cfg(body);
        let second = cfg(body);
        assert_eq!(first, second);
    }

    #[test]
    fn finds_the_enclosing_function_body() {
        let file = syn::parse_file(
            "fn helper() -> u32 { 1 }\n#[contractimpl] impl C { pub fn run() { let x = 1; } }",
        )
        .expect("source");
        let (body, range) = function_for_line(&file, 2).expect("contractimpl method");
        assert!(range.0 <= 2 && 2 <= range.1);
        assert!(body.stmts.len() == 1);
        assert!(function_for_line(&file, 99).is_none());
    }
}
