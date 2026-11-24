# Examples

Real, compilable example projects used to demonstrate the scanner and to act as
end-to-end fixtures. Each example is a standalone crate (excluded from the
workspace) and is built in CI.

| Example | Kind | Expected findings |
| ------- | ---- | ----------------- |
| [`clean-contract`](clean-contract/) | Soroban vault (clean) | none |
| [`vulnerable-contract`](vulnerable-contract/) | Soroban vault (intentionally vulnerable) | SS-001, SS-002, SS-004, SS-006, SS-007 |
| [`token`](token/) | Soroban fungible token (clean) | none |
| [`escrow`](escrow/) | Soroban escrow (clean) | none |
| [`vault`](vault/) | Soroban pausable vault (clean) | none |
| [`stellar-classic`](stellar-classic/) | Classic Stellar address tooling | none (not a Soroban project) |
| [`contracts`](contracts/) | 50 documented, source-only contract examples | not scanned automatically |

[`rule-pack-template`](rule-pack-template/) is a ready-to-copy starter template
for authoring new rule packs, including positive/negative fixtures, an offline
verification script, and authoring documentation.

[`external-rule-pack`](external-rule-pack/) is a data-only external rule pack,
not a compilable crate. It demonstrates the manifest schema, per-rule fixtures,
checksum validation, and signing instructions. For an authoring guide, see
[Rule Pack Authoring](../docs/pack-authoring.md).

## Build an example

Examples target `soroban-sdk` 28 and are excluded from the main workspace. Build
them directly by manifest path:

```bash
cargo check --manifest-path examples/token/Cargo.toml
```

## Scan an example

```bash
# The clean examples must pass a strict gate.
soroban-scan scan examples/token --fail-on high

# The vulnerable example is expected to produce findings.
soroban-scan scan examples/vulnerable-contract --fail-on none
```

## Safety

The examples are never executed, deployed, or signed. `vulnerable-contract`
contains deliberate security flaws and must not be used as a template.

Examples must never require network access at runtime and must never contain
secrets, keys, or real account credentials.

## Contract corpus

[`contracts/`](contracts/) holds 50 small, documented, MIT-licensed contract
examples grouped by category. They are source-only and are not built by the
example matrix. Validate their headers, categories, size, and README index with:

```bash
python tools/check_examples.py
```
