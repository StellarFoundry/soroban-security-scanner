# Mutation testing

`soroban-scan` uses [`cargo-mutants`](https://mutants.rs/) to measure assertion
strength in the core crate. Coverage alone can hide weak assertions; mutation
testing reports how many deliberately broken implementations the tests catch.

## Scope

The scheduled job mutates `crates/soroban-scan-core/src/engine.rs` and
`crates/soroban-scan-core/src/finding.rs` first. These contain the deduplication
pipeline and the fingerprint contract, where a silently wrong implementation
would affect baselines and reports. Expand the file list only after the baseline
is understood.

## Baseline

Measured locally on 2026-10-21 (Windows, `cargo-mutants 27.1.0`) for
`finding.rs` with `--cargo-test-arg --lib`:

| Outcome | Count |
| ------- | ----- |
| Caught | 6 |
| Missed | 65 |
| Timeout | 0 |
| Unviable | 3 |
| **Tested** | **74** |
| **Mutation score** | **6 / 71 = 8.5%** (caught ÷ (caught + missed)) |

This is a deliberately honest starting point. Most survivors are in
`Finding::identity` and related helpers, which currently have example tests but
not identity-sensitivity coverage. The scheduled job tracks the trend; it is
informational (`continue-on-error`) until the score improves, so a red run does
not block unrelated work.

No mutation score has been measured in CI yet. The table above is a local
baseline only; the first scheduled run records the CI numbers for both
`engine.rs` and `finding.rs` in its step summary and in the `mutants.out`
artifact.

## Tracking the score

The job summary prints the caught, missed, timeout, and unviable counts plus
the mutation score (`caught / (caught + missed)`) for the run. The full
`mutants.out` directory is uploaded as an artifact with 90-day retention, so
successive weekly runs can be compared by downloading the artifacts rather than
relying on a committed number. A change in the score is meaningful only when the
mutated file list is unchanged; update this page when the scope changes.

## Running locally

```bash
cargo install cargo-mutants --locked

cargo mutants \
  -p soroban-scan-core \
  --file crates/soroban-scan-core/src/finding.rs \
  --cargo-test-arg --lib \
  --timeout 60 \
  --jobs 2 \
  --no-shuffle
```

Results are written to `mutants.out/` (`caught.txt`, `missed.txt`,
`timeout.txt`, `unviable.txt`, and machine-readable `outcomes.json`). The
directory is ignored by git.

## CI

`.github/workflows/mutants.yml` runs weekly (Monday 04:00 UTC) and on demand.
It installs `cargo-mutants`, runs the scoped mutation suite, writes counts to
the job summary, and uploads `mutants.out` as an artifact. Use the manual
dispatch to re-check after adding tests.
