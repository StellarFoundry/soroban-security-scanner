# Fuzzing

Fuzz targets live in `fuzz/` and use cargo-fuzz (nightly toolchain; Linux or WSL).

| Target | Covers |
|---|---|
| `rule_engine` | Runs all rules on arbitrary parsed input; asserts no panic and bounded runtime |

## Run locally

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run rule_engine -- -max_total_time=60 -timeout=5 -rss_limit_mb=2048 -seed=1
```

## Design rules

- Offline and deterministic: no network, clock, RNG, or filesystem access.
- Targets never fabricate edges or findings; ambiguity is recorded, not guessed.
- Inputs are capped at 64 KiB.

## CI

The `Fuzz smoke` workflow builds the target and runs it for 60 seconds on every PR.

## Reproduce a crash

```bash
cargo +nightly fuzz run rule_engine fuzz/artifacts/rule_engine/<crash-file>
```