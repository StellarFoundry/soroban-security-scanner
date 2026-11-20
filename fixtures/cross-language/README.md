# Cross-language fixtures

These fixtures are valid projects in languages the scanner does not analyze.
They exist to prove that non-Rust input fails safely: the scan completes, reports
no Rust source files, and emits an aggregated `SYNTAX-001` diagnostic instead of
partially parsing another language.

| Fixture | Language | Expected behaviour |
| ------- | -------- | ------------------ |
| `typescript-soroban` | TypeScript | Skipped; one TypeScript diagnostic with `--unsupported-syntax`. |
| `solidity-vault` | Solidity | Skipped; one Solidity diagnostic with `--unsupported-syntax`. |
| `plain-cargo` | Rust | Supported; no `SYNTAX-001` and no findings claimed from another language. |

These are scanner fixtures, not production contracts. Do not add secrets or real
account addresses.
