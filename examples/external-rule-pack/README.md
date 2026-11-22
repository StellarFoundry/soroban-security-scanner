# Example external rule pack

This directory is a complete, data-only example of an external rule pack. It
contains exactly two rules and one fixture set per rule. It is not compiled and
contains no scanner plugin code; a pack is metadata only.

```text
examples/external-rule-pack/
  pack.toml                         schema v1 manifest with two rules
  verify.py                         offline checksum and fixture check
  fixtures/expl-101/                unbounded and bounded approval samples
  fixtures/expl-102/                stale and fresh oracle samples
```

## Rules

| Rule | Severity | Confidence | Fixtures |
| ---- | -------- | ---------- | -------- |
| `EXPL-101` Unbounded token approval | high | medium | `fixtures/expl-101/` |
| `EXPL-102` Oracle price used without freshness check | medium | low | `fixtures/expl-102/` |

`pack.toml` follows schema v1 described in
[rule pack signing](../../docs/rule-pack-signing.md): unknown fields are
rejected, rule ids are unique, and each `checksum` is `sha256:` plus the
lowercase hex digest of the rule's canonical JSON metadata. Canonical JSON
serializes `id`, `title`, `category`, `default_severity`, `default_confidence`,
`description`, and optional `remediation` in that exact order, with no spaces
and lowercase severity/confidence names.

## Validate offline

The script uses only the Python standard library and reads no network:

```bash
python examples/external-rule-pack/verify.py
```

The Rust integration test loads and validates the same manifest and checks every
checksum:

```bash
cargo test -p soroban-scan-core --test external_rule_pack_example
```

A Python unittest under `tests/` runs `verify.py` as part of normal test
discovery:

```bash
python -m unittest discover -s tests -p "test_external_rule_pack.py" -v
```

## Signing

Sign the **raw bytes** of `pack.toml` with an Ed25519 key. Do not sign a
normalized or rewritten copy; any byte change invalidates the signature.

1. Generate or load an Ed25519 signing key. Keep the private key out of the
   repository and CI logs.
2. Sign the exact bytes of `pack.toml`.
3. Write `pack.sig` next to the manifest using the detached signature format:

```toml
version = 1
algorithm = "ed25519"
key_id = "your-key-id"
signature = "<128 lowercase hex characters>"
```

4. Publish the public key (32-byte hex) to consumers through a trusted channel.
   Consumers add it to the `[[packs.trusted_keys]]` keyring with an `active`,
   `retired`, or `revoked` status.

Use a deterministic test key only for fixtures, never for a real pack. The
repository's own signed fixtures use synthetic keys under
`fixtures/rule-packs/`.

## Verification

Consumers verify the complete raw manifest and every rule checksum. During
development, an unsigned example can be loaded under `allow_unsigned`:

```rust
use soroban_scan_core::pack::{KeyRing, PackVerifier, VerificationPolicy};

let result = PackVerifier::verify_pack_dir(
    std::path::Path::new("examples/external-rule-pack"),
    &KeyRing::new(),
    VerificationPolicy::AllowUnsigned,
)?;
```

Production verification should use `VerificationPolicy::EnforceSigned` with a
trusted keyring. If `pack.sig` is present it must verify even when unsigned packs
are allowed; a tampered manifest is always rejected.

## Safety

The pack is metadata only. It grants no execution, filesystem, or network
permission, and the scanner never runs pack-supplied code.
