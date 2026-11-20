# Fixtures

Fixtures are small, self-contained inputs used by tests and the regression
corpus. They are **not** production code.

## Layout

```
fixtures/
  projects/        # whole mini-projects: Cargo.toml + src/
  corpus/          # regression fixtures grouped by rule/category
  adversarial/     # per-rule samples with unusual but valid syntax
  cross-language/  # valid non-Rust projects that must fail safely
  sdk-matrix/      # SDK version compatibility fixtures
  rule-packs/      # Rule pack fixtures for signing and verification tests
  reports/         # JSON scan reports used by comparison and dashboard tests
```

## Rules for fixtures

- Keep them minimal and readable.
- Each positive fixture (should trigger) is paired with a negative fixture
  (should not trigger).
- Every rule also has an adversarial sample under `adversarial/`. Its expected
  result (`trigger` or a documented `no-trigger` limit) lives in
  `adversarial/expectations.toml`.
- Never include real secrets or real contract addresses.
- Prefer synthetic examples over copied third-party code. Third-party code
  requires provenance; see [`docs/corpus-provenance.md`](../docs/corpus-provenance.md).

Exact formats and the expected-findings schema are defined in Phase 5.
