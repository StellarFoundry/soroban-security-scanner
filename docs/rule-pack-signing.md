# Rule Pack Signing and Verification

This document specifies the cryptographic signing, detached signature format,
and verification model for third-party rule packs.

## Overview

Community and external rule packs allow expanding scanner coverage without
modifying the core codebase. To prevent supply-chain attacks and tampering,
rule packs can be signed by trusted authors using Ed25519 detached signatures.

By default, the scanner fails closed: unsigned packs are rejected unless
explicitly permitted by configuration or the `--allow-unsigned-packs` flag.

## Manifest schema v1

`pack.toml` is a closed, data-only TOML document. The top-level `schema_version`
selects its format (`1` is currently supported); unknown fields and unsupported
schema versions are rejected. V1 carries rule metadata only. It has no script,
plugin, command, or binary field, and loading it never executes pack-supplied
code.

```toml
schema_version = 1

[pack]
name = "soroban-defi-rules"
version = "0.1.0"
description = "Community rule metadata for common Soroban DeFi attack vectors"
authors = ["Stellar Foundry"]
min_scanner_version = "0.2.0"
capabilities = ["rust_source_analysis"]

[[rules]]
id = "COMM-001"
title = "Unbounded slippage in swap invocation"
category = "defi"
default_severity = "high"
default_confidence = "medium"
description = "Flags swap calls where max_slippage is unconstrained or zero."
remediation = "Require an explicit nonzero slippage bound."
checksum = "sha256:41b4971ca5a0aa656406c4e86985de006119bac6a9aa36410eb2038f016c1e61"
```

A complete two-rule pack with per-rule fixtures, a validation script, and
signing instructions lives in
[`examples/external-rule-pack`](../examples/external-rule-pack/README.md).
For a step-by-step authoring guide and ready-to-copy starter template, see
[Rule Pack Authoring](pack-authoring.md) and
[`examples/rule-pack-template`](../examples/rule-pack-template/README.md).

The sample manifest is `fixtures/rule-packs/sample/pack.toml` and is
loaded and validated by:

```bash
cargo test -p soroban-scan-core --test pack_manifest
```

### Required metadata and compatibility

- `schema_version` must be `1`.
- `pack.name` uses 1-64 lowercase ASCII letters or digits separated by single
  hyphens. `pack.version`, `min_scanner_version`, and optional
  `max_scanner_version` use stable `MAJOR.MINOR.PATCH` versions. The inclusive
  scanner range must not be inverted.
- `pack.capabilities` is a non-empty, duplicate-free list of required scanner
  capabilities. V1 accepts only `rust_source_analysis` and
  `cargo_manifest_analysis`; these identify input support and grant no execution
  or filesystem/network permissions.
- A pack must contain at least one rule. Rule IDs use an uppercase prefix and a
  numeric suffix, such as `COMM-001`; IDs must be unique within the pack.
- Each rule needs non-empty title, category, and description, plus a required
  checksum. The checksum is lowercase `sha256:` plus 64 hex digits.

`PackManifest::load_file` and `PackManifest::parse_str` validate the full
schema, versions, identifiers, unique IDs and capabilities, and checksums.
`check_compatibility` additionally checks a scanner's version against the
inclusive min/max bounds and confirms it provides each required capability.
Manifest input is capped at 10 MiB before TOML parsing. Detached signature files are capped at 16 KiB.

### Rule checksums

A rule checksum is SHA-256 over the UTF-8 bytes of the compact JSON serialization
of its metadata, excluding `checksum`. Schema v1 serializes fields in this exact
order: `id`, `title`, `category`, `default_severity`, `default_confidence`,
`description`, and optional `remediation` (omitted when absent). Severity and
confidence use their lowercase names. JSON escaping and field order are fixed by
the v1 serializer. Prefix the lowercase hexadecimal digest with `sha256:`.

A checksum detects accidental or malicious metadata edits when compared with a
trusted expected checksum. It is not proof of publisher identity; `pack.sig`
provides authenticity for the complete raw manifest bytes when signature
verification is enabled.
## Pack format and detached signatures

A rule pack consists of:
1. `pack.toml`: The versioned, validated metadata manifest described above.
2. `pack.sig`: A detached signature file in TOML format:

```toml
version = 1
algorithm = "ed25519"
key_id = "stellar-foundry-active"
signature = "ca3b74a0dfe17d7a235e2c88b1908b0155d99e29678ed31a6b7b70829414268589b85f3f8ccd77584f037e4c7f5ca88392676723865bd53a9bd0f8fcaa9a0b03"
```

### Signature fields

| Field | Type | Description |
|---|---|---|
| `version` | integer | Signature schema version (current: `1`). |
| `algorithm` | string | Asymmetric signature algorithm (must be `ed25519`). |
| `key_id` | string | Identifier of the signing key in the trusted keyring. |
| `signature` | string | Hex-encoded 64-byte Ed25519 signature of the manifest bytes. |

## Verification policy

The verification policy controls how unsigned and signed packs are handled:

| Policy | Behavior |
|---|---|
| `enforce_signed` (default) | Rejects unsigned packs with an error. All packs must have a valid detached signature matching a trusted active or retired key. |
| `allow_unsigned` | Allows unsigned packs with an audit warning. Enabled via `--allow-unsigned-packs` or `packs.allow_unsigned = true`. |

Regardless of policy, if a detached signature (`pack.sig`) is present, it must
verify successfully. Tampered packs are always rejected.

## Key management

The scanner maintains a keyring of trusted public keys configured in `.soroban-scan.toml`:

```toml
[packs]
allow_unsigned = false

[[packs.trusted_keys]]
key_id = "stellar-foundry-active"
public_key = "a4b5c6... (32-byte hex)"
status = "active"

[[packs.trusted_keys]]
key_id = "stellar-foundry-2025"
public_key = "d1e2f3... (32-byte hex)"
status = "retired"

[[packs.trusted_keys]]
key_id = "compromised-key"
public_key = "112233... (32-byte hex)"
status = "revoked"
revocation_reason = "Compromised build server on 2026-05-01"
```

### Key lifecycle and rotation

Keys have three states:
- `active`: Authorized for signing current and upcoming packs.
- `retired`: Authorized for existing packs signed before rotation, but authors should not sign new releases with this key.
- `revoked`: Key is compromised or invalidated. Any pack signed with this key is rejected immediately.

When rotating keys:
1. Generate a new keypair and record its public key in the keyring as `active`.
2. Transition the existing active key to `retired`.
3. Existing distributed packs signed with the retired key continue to verify without breaking downstream users.
4. New packs are signed with the new active key.

### Key revocation

If a private key is leaked or compromised:
1. Mark the key status as `revoked` in configuration.
2. Provide a `revocation_reason` explaining the revocation.
3. Verification fails immediately with `RevokedKey` if any pack cites that key.

## Security considerations

- **Offline operation**: Verification runs entirely offline without network requests or external authority queries.
- **Bounded execution**: Manifest and payload sizes are capped (1 MiB for `pack.toml`, 64 KiB for `pack.sig`, 256 KiB for `conformance.toml`, max 256 rules) to prevent resource exhaustion attacks, and symlinks or path-escaping targets are rejected.
- **Zero secrets**: The scanner only reads and stores public keys. Private signing keys are never required or retained by the scanner.

## Safe loading and conformance tests

`PackLoader::load_dir` verifies signatures (fail-closed by default), rejects symlinks and oversized files, validates rule metadata, and enforces `pack.min_scanner_version <= current_version`.

To run the pack signing and conformance suites locally:

```bash
cargo test -p soroban-scan-core --test pack_signing
cargo test -p soroban-scan-core --test pack_conformance
```
