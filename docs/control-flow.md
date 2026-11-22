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

## Bounds

- `MAX_CFG_NODES` (256) caps nodes.
- `MAX_CFG_EDGES` (512) caps edges.
- `MAX_CFG_DEPTH` (32) caps control-flow nesting.

Hitting a cap sets `truncated = true` and stops adding nodes or edges. The
graph remains deterministic and readable.

## Reachability

Reachability is a graph search from the entry node. `reachability_at(line)`
reports `Reachable` when any node covering the line is reachable, `Unreachable`
when every covering node is unreachable, and `Unknown` when the graph does not
cover the line. Spans are line-granular, so a construct sharing a line with a
reachable node is considered reachable.

The CFG is used only to rank findings; it never adds, removes, or changes a
finding. See [Finding ranking](finding-ranking.md).

## Limitations

- The graph is per function and per file; there is no interprocedural CFG.
- `break`/`continue` destinations are not resolved; loops are conservatively
  treated as able to exit.
- Trait method signatures without bodies have no graph.
- Line-granular spans cannot distinguish two constructs on the same line.

Tests in `crates/soroban-scan-core/src/analysis/cfg.rs` cover branches, loops,
matches, returns, unknown constructs, caps, determinism, and line lookup.
