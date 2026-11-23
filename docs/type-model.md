# Type model

The scanner has no Rust type checker. It uses two small, syntactic type
facilities:

- `analysis::types` checks the type names visible at a contract entry point and
  reports names it cannot resolve as `TYPE-001` diagnostics.
- `rules::util` exposes the type facts the source makes visible, such as
  parameter types and the source type of a cast.

Both are per-file, data-only, and deterministic. The scanner never compiles or
executes the project, does not follow another file, and never guesses a type.
A name or source type it cannot see becomes unknown, and the diagnostic or rule
declines to act on it.

## What is modeled

| Construct | Modeled as | Example |
| --- | --- | --- |
| Entry-point parameter type | Rendered signature text, re-parsed and checked by name | `pub fn set(env: Env, amount: Amount)` |
| Typed local | `let` pattern with an explicit type annotation | `let limit: Limit = amount;` |
| Cast target | The type after `as` | `let _ = value as Target;` |
| Built-in and Soroban SDK name | Known without an import | `Env`, `Address`, `Option<u32>`, `u256` |
| File-local type declaration | Known by name in the same file, including inline modules | `struct Local;` |
| Conventional generic name | Known by convention | `T`, `K`, `V`, `T0` |
| Qualified path | Known when its root is `crate`, `self`, `super`, `std`, `core`, or `alloc` | `crate::Local` |
| Explicit import | Resolved through the file's `use` items | `use crate::token::Client as Token;` |
| Glob import | Reported as ambiguous | `use soroban_sdk::*;` then `Token` |
| Unimported name | Reported as unresolved | `Amount` with no `use` |

Type names nested inside a checked type are visited too. For example,
`Option<Missing>` reports `Missing`, while `Vec<u8>` reports nothing.

## Name resolution rules

For each public function in a `#[contractimpl]` block, the pass looks at
parameter types, typed locals, and cast targets. A type path is accepted, in
this order, when:

1. Its first segment is a qualified root: `crate`, `self`, `super`, `std`,
   `core`, or `alloc`.
2. Its first segment is a built-in or a Soroban SDK type the scanner knows by
   name. The list includes Rust prelude types, integer types (`u8` through
   `u256`, and signed equivalents), `Env`, `Address`, `Symbol`, `Bytes`,
   `BytesN`, `Map`, `Val`, `I128`, `U128`, `I256`, and `U256`.
3. Its first segment names a type declared in the same file: a `struct`, `enum`,
   `union`, `type` alias, or `trait`, including declarations inside inline
   modules.
4. Its first segment is a conventional generic name: one ASCII uppercase letter
   followed by zero or more ASCII digits.
5. Its first segment resolves through the file's imports to exactly one
   canonical path. Imports are per file; the resolver does not follow `pub use`
   chains or load another file. See
   [Import resolution](architecture/import-resolution.md).

Anything else is reported. Resolution has three outcomes:

- `Resolved` — exactly one import owns the name; no diagnostic.
- `Ambiguous` — a glob could supply the name, or the same local name is imported
  more than once. The diagnostic says `ambiguous type ...`.
- `Unresolved` — no import owns the name. The diagnostic says
  `unresolved type ...`.

Only the first path segment is checked by this pass. A self-qualified type
(`<T as Trait>::Assoc`) is skipped because its `qself` is ignored.

### Examples

```rust
use soroban_sdk::{contractimpl, Env};

#[contractimpl]
impl Contract {
    pub fn set(env: Env, amount: Amount) {
        let limit: Limit = amount;
        let _ = limit as Target;
    }
}
```

This produces three `TYPE-001` warnings, one for each construct:

- `unresolved type Amount in parameter type`
- `unresolved type Limit in local type annotation`
- `unresolved type Target in cast target`

The following names are not reported:

```rust
use soroban_sdk::{contractimpl, Env};

struct Local;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, count: u32, local: Local, optional: Option<Local>) -> Vec<u8> {
        let _: crate::Local = Local;
        Vec::new()
    }
}
```

`env`, `Env`, `u32`, `Local`, `Option`, `Vec`, `u8`, and the `crate::Local`
qualified path are all known. The return type is not part of the model.

Names inside generic arguments are visited. `Option<Missing>` reports
`Missing`; `Option<Local>` does not.

## Unknown and ambiguous propagation

A type name is never guessed. When a name cannot be resolved, the pass records
the construct, the type name, the first span, and whether the name was
ambiguous. It does not pick an import, invent a canonical path, or change rule
output.

`ImportMap::canonicalize` returns the original text for ambiguous and unresolved
paths. A rule that needs to classify an ambiguous name can inspect every
candidate with `Resolution::any_candidate`; the convention is to fail toward
reporting when any candidate matches the sensitive type. An unresolved path
falls back to the literal text. See
[Import resolution](architecture/import-resolution.md#ambiguity).

When a cast operand's source type is not visible, `CastFact::source_type` is
empty and its origin is `Other`. A rule must treat that as unknown; SS-018, for
example, does not report a cast whose source type it cannot see.

`TYPE-001` entries are diagnostics, not findings. They explain why a type-aware
rule may have stayed silent. The pass runs only in Soroban analysis mode.

### Aggregation and bounds

Repeated names are grouped by `(name, construct, ambiguous)`. One diagnostic is
emitted per group with the first span and an occurrence count, for example
`unresolved type Mystery in local type annotation (2 occurrences)`.

The pass is bounded per file:

- At most `MAX_TYPE_CHECKS` (256) type constructs are inspected.
- At most `MAX_TYPE_DIAGNOSTICS` (8) entries are emitted. When there are more
  groups, the eighth entry is an informational omitted-count notice.
- A recorded type name is truncated to `MAX_TYPE_NAME_LEN` (64) bytes.

The engine also caps the combined diagnostics from all files at 8 entries plus
an omitted-count notice.

## Cast operand types

`rules::util::cast_facts` extracts each `expr as Type` from a function body. The
target type is always the written type. The source type is populated only when
the source shows it:

| Evidence | Example | Result |
| --- | --- | --- |
| Parameter type | `amount: i128` then `amount as u32` | `source_type = "i128"` |
| Local type annotation | `let local: u32 = 1;` then `local as u8` | `source_type = "u32"` |
| Integer literal suffix | `1u64 as u32` | `source_type = "u64"` |
| Storage turbofish | `get::<_, u64>(&key)` then `stored as u32` | `source_type = "u64"` |
| Unknown operand | helper result, field, computed value | empty `source_type` |

References, parentheses, and groups are transparent. A storage type comes from
the last type argument of a `get` or `get_unchecked` turbofish; the search walks
back through the method chain and through `?` and `.await`.

The operand origin is classified separately:

- `Parameter` — a path that names a function parameter.
- `StorageRead` — a local initialized from a storage read, or an expression that
  textually combines `storage` with `get`/`get_unchecked`.
- `Local` — a local with a visible type annotation.
- `Other` — everything else, including literals and computed expressions.

`integer_bit_width` recognizes Rust integer type names, optionally behind `&` or
a qualified path (`&u32`, `std::primitive::u64`). `usize` and `isize` are
treated as 64-bit, the Soroban host width. Soroban's `u256` and `i256` are
included. Other types return `None`.

## Generic handling

There is no monomorphization, trait resolution, or type substitution. Generics
are handled only by name:

- A single uppercase letter plus optional digits (`T`, `U`, `T0`) is accepted as
  a conventional generic parameter and produces no `TYPE-001`.
- Generic arguments are still visited, so an unknown name inside `Option<T>` or
  `Vec<Missing>` is checked on its own.
- A self-qualified path such as `<T as Trait>::Assoc` is skipped entirely.
- A multi-letter or lowercase generic name (for example `Item` or `item`) is not
  recognized as conventional and is checked like any other name.
- Bounds, `where` clauses, associated types, and impl generics are not modeled.

## Limits

These limits are intentional and match the tests in `analysis/types.rs`,
`tests/unresolved_types.rs`, and `rules/util.rs`:

- The name pass runs only in Soroban analysis mode, and only for public
  functions in `#[contractimpl]` blocks. Private functions and free functions
  are not checked.
- Only plain identifier parameters are inspected. Destructuring patterns and
  `self` receivers are omitted because they cannot be matched to one name.
- Parameter types are rendered signature text and re-parsed; unparseable text is
  skipped rather than reported.
- The name pass checks parameter types, typed local patterns, and cast targets.
  Return types, struct fields, trait item signatures, and other type positions
  are not part of the model.
- Cast facts only know a local's type when the binding has an initializer and
  either an explicit annotation or a storage turbofish. A cast of a helper
  return value, field, or computed expression has no visible source type.
- Type aliases are known only by name. The alias target is not resolved, so a
  cast written through an alias is not classified as that target type.
- Analysis is per file. Cross-file re-exports, macros, and conditional
  compilation are not expanded or evaluated.
- Conventional generic detection is a name heuristic, not knowledge of declared
  type parameters.

## See also

- [Diagnostics](diagnostics.md) — the `TYPE-001` code and its level.
- [Import resolution](architecture/import-resolution.md) — per-file `use`
  resolution and ambiguity.
- [Taint analysis](taint-analysis.md) — unknown paths in data-flow propagation.
- [Control-flow graphs](control-flow.md) — explicit unknown nodes for
  unsupported control flow.
- [`SS-018`](rules/detectors/SS-018.md) — unchecked integer casts, built on cast
  facts.
