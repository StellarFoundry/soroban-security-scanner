# Control-flow graphs

`analysis::cfg` builds a small, deterministic control-flow graph (CFG) for one
function body. It is data-only: the builder walks the parsed syntax tree and
never executes or compiles the scanned project.

## API

- `AnalysisContext::cfg_for_function(source, function)` returns a cached
  `Arc<ControlFlowGraph>` for a function body.
- `build_function_cfg(block)` builds a graph directly from a `syn::Block`.
- `function_for_line(file, line)` finds the function body containing a line.
- `ControlFlowGraph` exposes `nodes`, `edges`, `entry`, `exit`, `truncated`, and
  `reachability_at(line)`.
- `Reachability` is `Reachable`, `Unknown`, or `Unreachable`.

Each `CfgNode` carries a stable `id`, a `NodeKind`, and a `Span`. Each
`CfgEdge` is a directed `from`/`to` pair. Node ids follow source traversal order
and edges are appended in creation order, so the same body always produces the
same graph.

## Node kinds

| Kind | Meaning |
| ---- | ------- |
| `Entry` | The single entry node (`id = 0`). |
| `Exit` | The single exit node (`id = 1`). |
| `Statement` | A straight-line statement or expression. |
| `Branch` | An `if` condition. |
| `Loop` | A `while`, `for`, or `loop` header. |
| `Match` | A `match` scrutinee. |
| `Return` | A `return` expression. |
| `Unknown` | A construct the builder deliberately does not model. |

`if`/`else` forks into the then and else paths (an omitted `else` keeps the
condition node as a fall-through). Loops add a back edge from the body exits to
the header. Every `match` arm gets its own edge. A `return` edges to `Exit` and
leaves no fall-through, so statements after it are marked unreachable rather
than hidden.

## Unsupported constructs

Macro statements, items inside blocks, `break`, `continue`, closures, and
`async` blocks become `NodeKind::Unknown` nodes. `break` and `continue` targets
are not modelled, so a bare `loop` continuation is an explicit `Unknown` node
instead of an invented edge; `while`/`for` can always skip the body and keep
their header as the exit. Unknown nodes are explicit: the builder never
fabricates an edge to make the graph look complete.

Each `ControlFlowGraph` also records how many unmodelled constructs it created
per `UnmodelledKind` in `unmodelled`. The engine aggregates those counts across
the scan and emits one bounded `CFG-002` diagnostic per kind, with a count and a
fixed label only. The diagnostic carries no path, line, function name, or source
text, so it identifies the kind of gap without echoing the scanned code. A
`CFG-002` diagnostic never changes a finding and is never a finding itself.

## Bounds

- `MAX_CFG_NODES` (256) caps nodes.
- `MAX_CFG_EDGES` (512) caps edges.
- `MAX_CFG_DEPTH` (32) caps control-flow nesting.

Hitting a cap sets `truncated = true` and stops adding nodes or edges. The
graph remains deterministic and readable. The engine emits a bounded `CFG-001`
diagnostic for each truncated public entry point (at most 8 per scan plus an
omitted-count notice), and rules that need complete reachability skip the
function instead of making a partial claim.

## Reachability

Reachability is a graph search from the entry node. `reachability_at(line)`
reports `Reachable` when any node covering the line is reachable, `Unreachable`
when every covering node is unreachable, and `Unknown` when the graph does not
cover the line. Spans are line-granular, so a construct sharing a line with a
reachable node is considered reachable.

The CFG ranks findings and lets rules that require complete reachability decide
whether to report. See [Finding ranking](finding-ranking.md).

The same pass also derives optional exploitability context. When the graph
covers a finding line, the finding records the reachability label and, if the
line is inside a Soroban contract entry point, the qualified entry-point name.
Incomplete evidence leaves the whole object absent. This context is additive
report metadata; it does not alter the graph, detection, severity, or
confidence.

## Limitations

- The graph is per function and per file; there is no interprocedural CFG.
- `break`/`continue` destinations are not resolved; loops are conservatively
  treated as able to exit.
- Trait method signatures without bodies have no graph.
- Line-granular spans cannot distinguish two constructs on the same line.

Tests in `crates/soroban-scan-core/src/analysis/cfg.rs` cover branches, loops,
matches, returns, unknown constructs, caps, determinism, and line lookup;
`tests/cfg_limits.rs` covers the diagnostic and the consumer skip behaviour.
