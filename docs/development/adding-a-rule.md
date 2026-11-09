# Adding a Rule

Adding a detector to `soroban-scan` touches four places:

1. A rule module in `crates/soroban-scan-core/src/rules/<module>.rs`
2. Registration in `crates/soroban-scan-core/src/rules/mod.rs`
3. Corpus fixtures in `fixtures/corpus/<ID>/{positive.rs,negative.rs,negative2.rs,negative3.rs}`
4. Detector documentation in `docs/rules/detectors/<ID>.md`

## Rule scaffold generator

Use `cargo xtask rule` (or its alias `cargo xtask new-rule`) to generate all four
artifacts from a rule id and title:

```bash
cargo xtask rule SS-042 "Unchecked ledger timestamp drift" \
  --category arithmetic \
  --severity medium \
  --confidence medium
```

Optional flags:

- `--module <snake_case>` — override the derived Rust module filename
- `--category <name>` — rule category (default: `authorization`)
- `--severity <level>` — default severity (default: `medium`)
- `--confidence <level>` — default confidence (default: `medium`)
- `--root <dir>` — repository root (default: workspace root)
- `--force` — overwrite existing scaffold files if present

### Safety guarantees

- **Idempotent by default:** refuses to overwrite any existing module, fixture,
  or documentation file unless `--force` is passed.
- **Bounded to the repository root:** validates the rule id (`SS-###`), module
  identifier, and relative paths, rejecting any traversal outside the repository.

## Completing the detector

After running the scaffold generator:

1. Fill in the AST inspection logic inside `analyze` in
   `crates/soroban-scan-core/src/rules/<module>.rs`.
2. Replace `fixtures/corpus/<ID>/positive.rs` with a minimal vulnerable contract
   that triggers `<ID>`, and add distinct safe patterns to `negative.rs`,
   `negative2.rs`, and `negative3.rs`.
3. Complete the problem, detection, limitation, false-positive, and remediation
   sections in `docs/rules/detectors/<ID>.md`.
4. Run `cargo test --all` and `cargo xtask docs`.

See [`../contributors/writing-rules.md`](../contributors/writing-rules.md) and
[`../rules/README.md`](../rules/README.md) for the full contributor guide.
