# Rule pack sandboxing and resource limits

Rule packs run in-process so they can reuse the scanner's parser and rule
metadata. Untrusted packs must never hang the scanner, exhaust memory, or emit
unbounded output. `soroban_scan_core::pack::sandbox` owns those limits.

## Limits

`PackLimits` bounds one pack run:

| Limit | Field | Default |
| ----- | ----- | ------- |
| Wall-clock time | `max_duration` | 5 seconds (`DEFAULT_MAX_DURATION`) |
| Output size | `max_output_bytes` | 1 MiB (`DEFAULT_MAX_OUTPUT_BYTES`) |
| Declared rules | `max_rules` | 10,000 (`DEFAULT_MAX_RULES`) |

Callers may tighten any limit; widening them is a policy decision that should
be documented in the pack's review.

## Running a pack

```rust
use soroban_scan_core::pack::sandbox::{run_bounded, PackLimits};

let limits = PackLimits::default();
let outcome = run_bounded(limits, manifest.rules.len(), move || {
    // Pack work; return a bounded textual diagnostic or finding summary.
    String::new()
})?;
```

`run_bounded` performs these steps:

1. Rejects a pack whose declared rule count exceeds `max_rules` before running
   any code.
2. Runs the pack on a worker thread.
3. Fails closed with `PackLimitError::Timeout` if it does not finish within
   `max_duration`.
4. Fails closed with `PackLimitError::OutputTooLarge` if the output exceeds
   `max_output_bytes`.
5. Converts a panic into `PackLimitError::PackFailed`, so a broken pack is a
   diagnostic rather than a crash.

## Isolation semantics

- A limit violation never yields partial findings; the pack run is discarded.
- A timeout detaches the worker thread because Rust cannot forcibly cancel it.
  Callers must treat a timeout as terminal and must not wait for the abandoned
  work.
- The output and rule-count caps bound the memory a pack can force the scanner
  to retain. They do not sandbox arbitrary native code; packs remain data-only
  in v1 and must not spawn processes or open sockets.

## Failure reporting

Report a pack failure as a scanner diagnostic (for example a `RULE-005`-style
warning) instead of aborting the scan. Combined with
[moderation](pack-moderation.md), this keeps one bad community pack from
affecting unrelated rules.

## Related

- [Rule pack registry](rule-pack-registry.md)
- [Rule pack signing and verification](rule-pack-signing.md)
- [Rule pack moderation](pack-moderation.md)
