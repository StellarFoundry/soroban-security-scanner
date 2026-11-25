# Benchmarks

The scanner's performance is measured with a dependency-free in-process
benchmark. This keeps the measurement reproducible and avoids adding a benchmark
framework before it is needed.

## Running

```bash
cargo run --release -p soroban-scan-core --example benchmark
```

The benchmark generates synthetic `#[contractimpl]` sources with 100, 1,000,
5,000, and 10,000 entry points, and reports throughput.

It also reports the process's **peak resident memory** for each size. On Linux
(the CI platform) this is read from `/proc/self/status` (`VmHWM`); platforms
without an equivalent zero-dependency probe print `n/a` rather than guessing.
Watch this column for changes that trade throughput for memory, which matters for
CI container limits.

## Methodology

- The source is generated in memory, so the numbers isolate parsing and detector
  cost from filesystem I/O.
- The scanner runs all built-in rules.
- A warm-up scan precedes each measurement.

## Baseline (illustrative)

Measured on a developer Windows machine with Rust 1.97.1. Treat these as
order-of-magnitude guidance, not guarantees.

| Entry points | Source size | Release time | Release rate |
| -----------: | ----------: | -----------: | -----------: |
| 100 | 24.6 KB | 39.5 ms | ~2,530/s |
| 1,000 | 246.9 KB | 404.7 ms | ~2,470/s |
| 5,000 | 1.24 MB | 1.83 s | ~2,730/s |
| 10,000 | 2.48 MB | 3.61 s | ~2,770/s |

Debug builds are roughly 5-8× slower; always benchmark with `--release`.

## End-to-end (CLI) benchmark

The in-process example measures parsing and detection on synthetic sources. To
measure the **combined** system — project discovery, parsing, scanning and
report generation — time the real release binary:

```bash
cargo build --release -p soroban-scan-cli
python tools/benchmark.py --target examples/vulnerable-contract --runs 10
```

The script performs one warm-up run, then reports min/median/mean/max over the
requested runs. It uses only the Python standard library. Compare before/after on
the same machine, the same target and the same profile, and always benchmark a
`--release` build.

## CI regression threshold

The `Benchmark regression` CI job runs the CLI benchmark on `ubuntu-latest` and
compares the median against the committed
[`tools/benchmark_baseline.json`](../../tools/benchmark_baseline.json). It fails
only when the median is worse than `baseline_median_ms * threshold_factor`
(currently a wide 6x margin), which catches accidental quadratic behaviour
without failing on normal runner variance. The job is ubuntu-only; timings from
other operating systems are not comparable.

To refresh the baseline after an intentional performance change, run the same
command on the same runner type and commit the result:

```bash
python tools/benchmark.py --update-baseline
```

The measurement and comparison logic is covered by
`tests/tools/test_benchmark_threshold.py`.

## Scan latency by project size

To measure how scan latency scales across project sizes (small, medium, large), use
the `--by-project-size` flag:

```bash
python tools/benchmark.py --by-project-size --runs 5
```

This benchmarks three representative fixture project tiers:
- **Small:** `fixtures/projects/generic-rust` (single package, minimal entrypoints)
- **Medium:** `fixtures/projects/soroban-confirmed` (Soroban contract with storage and auth checks)
- **Large:** `fixtures/projects/monorepo` (multi-crate contract workspace with token, vault, adapter)

It records the min, median, mean, max, and **p95** latency for each tier, helping
evaluate performance budgets as projects scale. Optionally write the results to JSON
using `--json-out <path>`.

## Dashboard artifact

Every `tools/benchmark.py` run writes a static dashboard to
`target/benchmark-dashboard/` (override the location with `--artifact-dir`):

- `benchmark.json` records the target label, runner, min/median/mean/max,
  baseline, threshold factor, failure limit, pass/fail status, and any
  regression messages. Its `schema_version` is `1`.
- `index.html` renders that JSON as a summary with inline CSS. It loads no
  scripts or external resources, so it opens offline and renders in a browser
  without network access.

The target is stored as a repository-relative path; a target outside the
repository is reduced to its directory name. Neither file contains source text
or absolute paths, so the artifact is safe to publish from CI.

```bash
python tools/benchmark.py --runs 5
python tools/check_benchmark_artifact.py target/benchmark-dashboard
```

The `Benchmark regression` CI job runs the validator, so a malformed,
non-self-contained, or path-leaking artifact fails the job. The job uploads
`benchmark.json` and `index.html` as the `benchmark-dashboard` artifact with a
bounded 14-day retention. Dashboard generation and validation are covered by
`tests/tools/test_benchmark_dashboard.py`.

## Frontend performance budgets

`crates/soroban-scan-core/tests/frontend_budgets.rs` loads the conformance
fixture (`fixtures/projects/soroban-confirmed`) through the default `Frontend`
and enforces two budgets in the normal `cargo test --all` CI job:

| Budget | Bound | Measured how |
| ------ | ----- | ------------ |
| Time | 2 seconds | Wall-clock for one warm `load` in the debug test profile. |
| Peak allocation | 32 MiB | A test-local counting global allocator; peak bytes allocated, not RSS. |

The fixture is intentionally tiny, so the bounds are far above normal runs
(roughly milliseconds and tens of KiB on a developer machine). They fail when a
change makes loading dramatically slower or allocate an order of magnitude more
memory, while tolerating slow or virtualized CI runners. Allocation counting is
deterministic and works on every OS; no `/proc` or platform-specific probe is
involved.

A failure prints the measured value and the budget, and points at the frontend
rather than asking for a larger limit. Raise a budget only with measurements
from a clean baseline and an explanation in the pull request. The test uses a
separate integration binary with a single test so parallel test allocations do
not distort the peak.

## Pathological-input regression

`crates/soroban-scan-core/tests/performance.rs` asserts generous upper time
bounds for adversarial inputs (deeply chained helpers, many entry points with
cross-calls). These guard against algorithmic regressions — such as quadratic
helper-summary expansion — and are not precise benchmarks.

## Baseline comparison

`crates/soroban-scan-core/examples/benchmark_baseline.rs` measures parsing,
index construction and comparison for synthetic baselines. Comparison builds one
fingerprint index per run and makes a single pass over the findings.

```bash
cargo run --release -p soroban-scan-core --example benchmark_baseline
```

Illustrative release numbers (Windows 11, Rust 1.99.1; `peak_rss` is reported on
Linux only):

| Entries | JSON bytes | Parse | Index | Compare | Resolved |
| ------- | ---------- | ----- | ----- | ------- | -------- |
| 10,000 | 1.7 MB | 13 ms | 2 ms | 23 ms | 5,000 |
| 50,000 | 8.8 MB | 51 ms | 13 ms | 132 ms | 25,000 |
| 200,000 | 35 MB | 212 ms | 43 ms | 636 ms | 100,000 |

Comparison cost stays linear in findings plus baseline entries. Baseline
documents above 64 MiB are rejected before parsing, so untrusted input cannot
force unbounded memory use.

## Interpreting results

- Cost scales linearly with source size, which is expected for a
  parse-and-visit pipeline.
- The dominant cost is Rust parsing (`syn`). Detector evaluation is negligible
  by comparison.
- Optimize parsing and traversal before micro-optimizing individual rules.

## Adding measurements

If a change plausibly affects performance:

1. Record the "before" numbers from a clean checkout.
2. Apply the change.
3. Record the "after" numbers on the same machine, same profile.
4. Include both in the pull request.

Do not optimize speculatively: measure first.
