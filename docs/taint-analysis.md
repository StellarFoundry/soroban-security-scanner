# Taint analysis vocabulary

`analysis::taint` provides one shared, bounded vocabulary for "user-controlled
data reaches a sensitive operation". It is a library analysis for rule authors,
not a security finding on its own. A tainted flow only describes provenance; a
rule must decide whether that provenance is a problem.

The analysis is syntactic, data-only, and deterministic. It never compiles or
executes the scanned project, and it does not perform whole-program analysis.

## Descriptors

Two plain data types describe the vocabulary:

- `SourceDescriptor` — a name, a `SourceKind`, and a `Span`.
  - `FunctionParameter`: a public contract entry-point parameter other than the
    `Env`.
  - `DecodedInput`: a local whose initializer calls a documented decoder such as
    `from_xdr`, `from_bytes`, `from_string`, `from_str`, or `try_from` and whose
    value is still tainted. `source_descriptors` reports the decoder as
    provenance; it never seeds taint on its own.
- `SinkDescriptor` — a name, a `SinkKind`, an optional zero-based argument
  index, and a `Span`.
  - `AuthSubject`: the receiver of `require_auth` /
    `require_auth_for_args`, or the first argument of the free-function form.
  - `TransferAmount`: the last argument of `transfer` / `transfer_from`.
  - `PrivilegedAddress`: an address argument of a documented privileged token
    call — `transfer` (to), `transfer_from` (from, to), `approve` (spender),
    `mint`/`burn`/`clawback` (subject), and `burn_from` (from).

Rule authors register descriptors in a `DescriptorRegistry` and query them with
`sources()`, `sinks()`, `sources_of_kind()`, and `sinks_of_kind()`. Registration
returns a typed `DescriptorError` for empty names, oversized names, control
characters, invalid spans, out-of-range argument indexes, and the fixed
`MAX_SOURCES` / `MAX_SINKS` limits. Duplicate descriptors are ignored and every
query is ordered by span.

Descriptors are values only. There are no callbacks, traits objects, or script
hooks, so a rule pack cannot execute arbitrary code through registration.

## Propagation

`auth_subject_flows(file, entry)` and `transfer_amount_flows(file, entry)` run a
fixed-point propagation pass over one entry point. `address_argument_flows(file,
entry)` runs the same pass with privileged-token address arguments as sinks:

- Every non-`Env` parameter is a source.
- `let` bindings with a plain identifier pattern and plain assignments inherit
  taint from their right-hand side.
- References, parentheses, casts, `?`, and `await` are transparent.
- Arithmetic, method calls, field access, indexing, and free-function calls
  record a `Transformed` path with the rendered expression (bounded to 120
  bytes) when the expression still fits.
- Calls to functions defined in the same file propagate taint through their
  return value. Every `return` expression and the function's tail expression are
  merged, so a caller binding inherits the union of the origins a helper can
  return.
- Intra-file helpers are followed, mapping caller arguments to helper parameters
  by position, up to `MAX_HELPER_DEPTH` and `MAX_HELPERS`. Each helper is visited
  at most once per entry point, using the first tainted call site.
- If a value has more than one tainted origin, the path is `Unknown` with a
  reason instead of picking one source. The value is still reported. The same
  merge applies at control-flow joins: a value tainted on one branch, loop
  iteration, or return path is still tainted, and incompatible origins become
  `Unknown`.

Paths are capped by `MAX_PATH_STEPS`. When a path would exceed the cap the
result is `Unknown`, never a guessed longer path.

## Documented sanitizers

An unconditionally assigned value passed through one of these names is treated
as sanitized and is **not** reported as a flow.

Authorization subjects (`AUTH_SANITIZERS`):

`validate_address`, `normalize_address`, `checked_address`,
`verified_address`, `sanitize_address`.

Token amounts (`AMOUNT_SANITIZERS`):

`checked_add`, `checked_sub`, `checked_mul`, `checked_div`, `checked_neg`,
`try_from`, `try_into`, `clamp`, `min`, `max`, `validate_amount`,
`checked_amount`, `verified_amount`.

Privileged address arguments (`ADDRESS_SANITIZERS`) use the same documented
address-validation names as `AUTH_SANITIZERS`: `validate_address`,
`normalize_address`, `checked_address`, `verified_address`,
`sanitize_address`. An `Address` type annotation alone is never treated as
validation; only a documented helper name clears the flow.

The lists are explicit so a typo or an unrelated helper does not silently clear
taint. Sanitizers are matched by method or free-function **name only**; there is
no receiver-type or argument check. Extending a list is a security-relevant
change and requires tests for the sanitized and unsanitized paths.

### Conditional sanitization

Propagation is not path-sensitive. When a tainted binding is reassigned to a
sanitized value only inside an `if`, loop, or `match` arm, the analysis cannot
prove the sanitizer ran on every path. In that case the value becomes
`TaintPath::Unknown` and the flow is still reported, instead of being silently
cleared:

```rust
let mut subject = owner;
if trusted {
    subject = validate_address(&env, owner);
}
subject.require_auth(); // reported with an Unknown path
```

An unconditional reassignment clears the taint normally. The same conservative
rule applies to amount and address sanitizers.

## Limits

- The analysis is per entry point and per file. Cross-file helpers, macros, trait
  dispatch, and type inference are not followed.
- Rules call `auth_subject_flows`, `transfer_amount_flows`, or
  `address_argument_flows` with entry points from `contract_entry_functions`
  (public `#[contractimpl]` functions). The analysis itself does not decide
  what an entry point is.
- Only simple identifier patterns are tracked. Tuple/struct destructuring,
  field/index assignment targets, closures, `async` blocks, and method receivers
  that are expressions are outside the model.
- The propagation pass is not path-sensitive: every branch is visited once and a
  fixed point is reached syntactically. Loops do not get an implicit second
  tainted iteration. No path feasibility is claimed; a merged value at a
  control-flow join records that taint *may* reach the sink, not that any
  particular path executes. Ambiguous joins become `Unknown` and stay visible.
- A bare comparison (`if amount > 0`) is not a sanitizer for this analysis;
  existing detector logic can still recognize such guards. Only the documented
  helper names stop taint.
- `transfer` and `transfer_from` are matched by method name, like SS-014, so an
  unrelated method with that name can produce a flow. The sink descriptor
  records the span, and the consumer decides whether to report it.
- Privileged address sinks are matched by call name and fixed argument index;
  there is no receiver-type check, so an unrelated `transfer`-shaped method can
  produce a flow. Only the documented argument positions are inspected.
- Work is capped by `MAX_SOURCES`, `MAX_SINKS`, `MAX_FLOWS`, `MAX_PATH_STEPS`,
  `MAX_EXPRESSION_LEN`, `MAX_HELPER_DEPTH`, `MAX_HELPERS`, and
  `MAX_ITERATIONS`. Exceeding a cap produces `Unknown` or truncation, never a
  guessed path.

## Diagnostics for unresolved flows

`unresolved_flow_diagnostics(source, relative_path)` reports why a taint rule may
have declined to fire. It runs the same per-entry-point analysis as the flow
APIs and records three bounded reasons:

- `unresolved_call`: a free function called with tainted arguments is not
  defined in the file, so the analysis cannot follow it.
- `unsupported_syntax`: a tainted value reaches a construct the propagation pass
  does not model (for example a `match` expression or a closure).
- `truncated`: a helper, depth, or flow bound was reached.

The records are aggregated per source file by `(reason, sink)` with the first
span, bounded to `MAX_TAINT_DIAGNOSTICS`, and emitted in the report as
`TAINT-001` diagnostics. Only counts and fixed labels are included: no
expression, argument, literal, function name, or other source text is stored or
reported. A `TAINT-001` diagnostic never changes a finding and is never a finding
itself.

## See also

- [Diagnostics](diagnostics.md) - `TYPE-001` for unresolved and ambiguous type
  names and `TAINT-001` for unresolved taint flows.
- [`SS-014`](rules/detectors/SS-014.md) — token transfer amount validation.
- [`SS-044`](rules/detectors/SS-044.md) — cross-contract address argument validation, built on `address_argument_flows`.
- [`SS-018`](rules/detectors/SS-018.md) — unchecked integer casts.
- [Control-flow graphs](control-flow.md) — the per-function CFG used for
  reachability.
- [Finding ranking](finding-ranking.md) — how reachability and impact order
  output.
