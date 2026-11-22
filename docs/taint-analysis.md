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
  - `DecodedInput`: a local produced by a documented decoder such as
    `from_xdr`, `from_bytes`, `from_string`, `from_str`, or `try_from`.
- `SinkDescriptor` — a name, a `SinkKind`, an optional zero-based argument
  index, and a `Span`.
  - `AuthSubject`: the receiver of `require_auth` /
    `require_auth_for_args`, or the first argument of the free-function form.
  - `TransferAmount`: the last argument of `transfer` / `transfer_from`.

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
fixed-point propagation pass over one entry point:

- Every non-`Env` parameter is a source.
- `let` bindings and assignments inherit taint from their right-hand side.
- References, parentheses, casts, `?`, and `await` are transparent.
- Arithmetic, method calls, field access, indexing, and free-function calls
  record a `Transformed` path with the rendered expression (bounded to 120
  bytes) when the expression still fits.
- Intra-file helpers are followed, mapping caller arguments to helper parameters
  by position, up to `MAX_HELPER_DEPTH` and `MAX_HELPERS`.
- If a value has more than one tainted origin, the path is `Unknown` with a
  reason instead of picking one source. The value is still reported.

Paths are capped by `MAX_PATH_STEPS`. When a path would exceed the cap the
result is `Unknown`, never a guessed longer path.

## Documented sanitizers

A value passed through one of these names is treated as sanitized and is **not**
reported as a flow:

Authorization subjects (`AUTH_SANITIZERS`):

`validate_address`, `normalize_address`, `checked_address`,
`verified_address`, `sanitize_address`.

Token amounts (`AMOUNT_SANITIZERS`):

`checked_add`, `checked_sub`, `checked_mul`, `checked_div`, `checked_neg`,
`try_from`, `try_into`, `clamp`, `min`, `max`, `validate_amount`,
`checked_amount`, `verified_amount`.

The lists are explicit so a typo or an unrelated helper does not silently clear
taint. Extending a list is a security-relevant change and requires tests for the
sanitized and unsanitized paths.

## Limits

- The analysis is per entry point and per file. Cross-file helpers, macros, trait
  dispatch, and type inference are not followed.
- Only `#[contractimpl]` public functions are treated as entry points.
- A bare comparison (`if amount > 0`) is not a sanitizer for this analysis;
  existing detector logic can still recognize such guards. Only the documented
  helper names stop taint.
- `transfer` is matched by method name, like SS-014, so an unrelated method with
  that name can produce a flow. The sink descriptor records the span, and the
  consumer decides whether to report it.
- Work is capped by `MAX_SOURCES`, `MAX_SINKS`, `MAX_FLOWS`, `MAX_HELPER_DEPTH`,
  `MAX_HELPERS`, and `MAX_ITERATIONS`.

## See also

- [Diagnostics](diagnostics.md) — `TYPE-001` for unresolved and ambiguous type
  names.
- [`SS-014`](rules/detectors/SS-014.md) — token transfer amount validation.
- [`SS-018`](rules/detectors/SS-018.md) — unchecked integer casts.
