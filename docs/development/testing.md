# Testing Guide

Testing is a first-class requirement. Security tooling that is not tested is
worse than no tooling, because it creates false confidence.

## Test layers

| Layer | Location | Purpose |
| ----- | -------- | ------- |
| Unit | `#[cfg(test)]` modules next to code | Individual functions and rules |
| Integration | `crates/*/tests/` | End-to-end crate behavior |
| Fixtures | `fixtures/` | Positive/negative source samples |
| Regression | `fixtures/corpus/` | Pins expected findings to prevent regressions |
| Adversarial | `fixtures/` + parser tests | Malformed, hostile, and pathological input |

## Running tests

```bash
cargo test --all
```

Python-only CI helpers (the GitHub comment and check-run scripts) have their own
standard-library test suite:

```bash
python -m unittest discover -s tests -v
```

Run a single test:

```bash
cargo test -p soroban-scan-core -- --nocapture some_test_name
```

## Rules for security-sensitive tests

- Every rule ships with at least one **positive** fixture (must trigger) and one
  **negative** fixture (must not trigger).
- False-positive tests are as important as true-positive tests.
- Parser features require malformed-input tests.
- Any future network/CI integration requires permission and error-path tests.

## Fixture conventions

Fixtures live under `fixtures/` and are grouped by purpose:

```
fixtures/
  projects/   # whole mini-projects (manifests + source)
  corpus/     # regression corpus fixtures
```

Each fixture directory should be self-describing, for example:

```
fixtures/corpus/authorization/missing-auth-positive/
  Cargo.toml
  src/lib.rs
  expected.json      # expected findings (rule ids, lines)
```

Exact formats are defined in Phase 5. Until then, fixtures are plain source
samples.

## Golden report snapshots

`crates/soroban-scan-core/tests/report_snapshots.rs` scans the full regression
corpus and compares the JSON and SARIF renderings with committed golden files
under `crates/soroban-scan-core/tests/snapshots/`. The project root is
normalized to `fixtures/corpus`, so the snapshots do not contain absolute paths,
timestamps, or timings.

Update the snapshots only when a machine-format change is intentional:

```bash
UPDATE_SNAPSHOTS=1 cargo test -p soroban-scan-core --test report_snapshots
```

PowerShell:

```powershell
$env:UPDATE_SNAPSHOTS="1"; cargo test -p soroban-scan-core --test report_snapshots
```

Review the diff under `crates/soroban-scan-core/tests/snapshots/` before
committing it. Never update a snapshot merely to make an unrelated test pass;
explain the format change in the pull request and update the changelog when the
report contract changes.

## Determinism

Tests assert that scanning the same fixture twice produces byte-identical
machine-readable output.

## Fuzzing

The parser consumes untrusted source, so it is fuzzed with
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz). The target lives in
`fuzz/` (a separate workspace, excluded from the main build) and calls
`parse_source` on arbitrary bytes decoded as lossy UTF-8; it performs no
filesystem access.

Install the toolchain and run it locally:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
cargo fuzz run parse_source
```

CI runs a bounded smoke case from the scheduled `Fuzz` workflow:

```sh
cargo fuzz run parse_source -- -runs=2000
```

Minimize any regression with `cargo fuzz tmin parse_source <input>` and add it
under `fixtures/` as a permanent regression case.