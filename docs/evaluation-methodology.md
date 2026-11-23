# Evaluation Methodology

This page explains what the scanner's fixture checks and performance benchmarks
measure, how to reproduce them, and what they do not establish. The scanner has
no published aggregate precision or recall score: its current curated fixture
suite is a regression set, not a representative labeled sample of production
contracts.

## Detection corpus and expected findings

The primary rule corpus is `fixtures/corpus/`. Each registered detector has a
small positive example expected to produce at least one finding for that rule,
and negative examples expected to produce none for that rule. The Rust rules use
`.rs` fixtures; SS-015 uses `Cargo.toml` fixtures. The examples are intentionally
small and focus on one detector condition at a time. The checks are in
`crates/soroban-scan-core/tests/corpus.rs`.

`fixtures/adversarial/expectations.toml` records one unusual-syntax case for
every registered detector. Each entry explicitly says `trigger` or
`no-trigger` and gives a reason. A documented `no-trigger` is a known detection
limit, not a positive vulnerable sample. The test in
`crates/soroban-scan-core/tests/adversarial_corpus.rs` fails if an expectation is
missing, malformed, or contradicted by the scanner. Ambiguous behavior should
be recorded and reviewed; it must not be guessed into a finding.

The per-rule counts in
`crates/soroban-scan-core/tests/snapshots/finding_counts.toml` pin the number of
findings over the corpus and expose unintended changes. Deterministic JSON and
SARIF snapshots under `crates/soroban-scan-core/tests/snapshots/` check report
serialization. Third-party fixtures are a separate data source and must follow
[`Corpus Licensing and Provenance`](corpus-provenance.md).

The corpus tests reproduce the expected outcomes and checked-in counts:

```bash
cargo test -p soroban-scan-core --test corpus --test adversarial_corpus --test finding_counts --test report_snapshots
```

A passing test means the scanner agrees with these fixture labels. It does not
mean every finding is a true vulnerability or that an unreported vulnerability
is absent.

## Precision and recall

For a future explicitly labeled evaluation set, calculate metrics per rule from
labeled fixture/rule pairs:

- **True positive (TP):** a labeled positive fixture produces the expected
  rule's finding.
- **False negative (FN):** a labeled positive fixture does not produce that
  finding.
- **False positive (FP):** a labeled negative fixture produces that rule's
  finding.
- **True negative (TN):** a labeled negative fixture produces no finding for
  that rule.
- **Precision:** `TP / (TP + FP)`.
- **Recall:** `TP / (TP + FN)`.

Report the positive and negative sample counts with any such score, and define
how multiple findings in one fixture are counted. Do not treat the adversarial
`no-trigger` cases as missed vulnerabilities: they document known limits, not
positive labels. The current test suite asserts fixture expectations and finding
counts, but does not calculate aggregate TP/FP/FN/TN or publish a precision or
recall number. Do not derive or claim a score from passing tests alone.

## Performance benchmarks

There are two distinct benchmarks. The in-process benchmark generates synthetic
Soroban implementations with 100, 1,000, 5,000, and 10,000 entry points. It
warms each generated input and times one scan using all built-in rules. It
isolates parsing and detection from filesystem and report I/O. Run it with a
release build:

```bash
cargo run --release -p soroban-scan-core --example benchmark
```

The output includes generated source bytes, findings, elapsed time,
entry-points-per-second, and peak resident memory when the platform exposes it.
(The current output header says `files/s`; the value is generated entry points
per second because each sample is one generated source file.) The illustrative
numbers in [`Benchmarks`](development/benchmarks.md) are historical samples,
not universal targets.

The end-to-end benchmark times project discovery, parsing, scanning, and JSON
report generation on the vulnerable example project. It performs one warm-up,
then reports min, median, mean, and max for the requested measured runs. The
committed Ubuntu baseline and its wide regression threshold are in
`tools/benchmark_baseline.json`:

```bash
cargo build --release -p soroban-scan-cli
python tools/benchmark.py --target examples/vulnerable-contract --runs 10 --json-out target/benchmark-stats.json
```

Each run also writes the static dashboard described in
[`Benchmarks`](development/benchmarks.md): `benchmark.json` and a
self-contained `index.html` under `target/benchmark-dashboard/`.

The script builds the release binary automatically if it is missing. It prints
the measured statistics and baseline threshold; it exits nonzero if the median
exceeds the configured limit. To reproduce the baseline comparison benchmark
for synthetic JSON finding sets, run:

```bash
cargo run --release -p soroban-scan-core --example benchmark_baseline
```

Wall-clock results depend on CPU, operating system, compiler, load, and build
profile. Compare runs on the same machine and toolchain. The CLI threshold is a
coarse regression guard, not a claim that all listed sample sizes run in a fixed
time. Update a committed baseline only with measurements from the same CI runner
type and explain the change in the PR.

## Limits and interpretation

- The fixtures are hand-authored, curated regression examples. They are not
  randomly sampled or prevalence-weighted, so fixture results cannot estimate
  real-world precision or recall.
- Positive and negative cases isolate known detector patterns. They do not cover
  every syntax form, macro expansion, cross-file helper, deployment behavior, or
  business-logic path.
- Adversarial expectations document selected edge cases, not an exhaustive
  adversarial search. A known `no-trigger` is retained as an explicit limitation
  rather than silently treated as a scanner success on a positive sample.
- Synthetic throughput inputs are generated in memory and do not represent
  production repository composition. The CLI benchmark uses one small example
  project; neither benchmark measures analysis quality.
- A clean scan is not evidence that a contract is secure. Findings require
  human validation, and static analysis cannot prove runtime exploitability.
  See [Analysis Methodology](analysis-methodology.md) for detector evidence,
  confidence, and additional analysis limits.
