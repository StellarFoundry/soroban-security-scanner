# Fixtures

Fixtures are small, self-contained inputs used by tests and the regression
corpus. They are **not** production code.

## Layout

```
fixtures/
  projects/   # whole mini-projects: Cargo.toml + src/
  corpus/     # regression fixtures grouped by rule/category
  reports/    # JSON scan reports used by comparison and dashboard tests
```

## Rules for fixtures

- Keep them minimal and readable.
- Each positive fixture (should trigger) is paired with a negative fixture
  (should not trigger).
- Never include real secrets or real contract addresses.
- Prefer synthetic examples over copied third-party code.

Exact formats and the expected-findings schema are defined in Phase 5.
