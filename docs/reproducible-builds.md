# Reproducible build verification

A reproducible build lets you check that a release binary was produced from the
source you can read. This project ships a verification script that rebuilds the
CLI and reports whether the result matches byte for byte. It does **not** claim
that every build is reproducible; it gives you the evidence to decide.

## Run the check

```bash
python tools/verify_reproducible_build.py --manifest-path Cargo.toml \
  --package soroban-scan-cli
```

The script:

1. records `rustc -Vv` and `cargo -V`;
2. builds the package twice in separate target directories with
   `SOURCE_DATE_EPOCH=0` and `CARGO_INCREMENTAL=0`;
3. hashes the resulting binary with SHA-256; and
4. reports `reproducible` when the two digests match.

Exit codes: `0` when the digests match, `1` on a mismatch, `2` when a build
fails. Add `--json` for a machine-readable report, or `--work-dir` to keep the
two build trees for inspection.

## Inputs that matter

Record these with every verification:

| Input | How to capture it |
| ----- | ----------------- |
| Rust toolchain | `rustc -Vv` (the script records it) |
| Cargo version | `cargo -V` (the script records it) |
| Build environment | `SOURCE_DATE_EPOCH`, `CARGO_INCREMENTAL`, and any `--env KEY=VALUE` overrides |
| Locked dependencies | `Cargo.lock` (the script builds with `--locked`) |
| Linker and system libraries | Your platform's toolchain notes |

Pass additional inputs with `--env`, for example:

```bash
python tools/verify_reproducible_build.py --env "RUSTFLAGS=-C debuginfo=0"
```

## When the digests differ

A mismatch is a finding, not a script failure to hide. The report lists likely
causes:

- a different Rust toolchain or Cargo version;
- incremental compilation or a reused target directory;
- absolute build paths embedded in debug info or panic messages;
- parallel codegen, or a non-deterministic proc-macro or linker;
- different `RUSTFLAGS`, profile variables, or locale;
- different linker or system libraries.

Re-run with the same toolchain and a clean work directory before treating the
difference as a supply-chain concern.

## Relationship to release artifacts

Release archives are published with `SHA256SUMS` and a GitHub build-provenance
attestation. See [supply-chain](supply-chain.md) for what is and is not signed.
A successful local rebuild corroborates the published digest; it does not
replace the attestation.
