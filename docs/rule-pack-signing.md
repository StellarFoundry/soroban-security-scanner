# Rule Pack Signing and Verification

This document specifies the cryptographic signing, detached signature format,
and verification model for third-party rule packs.

## Overview

Community and external rule packs allow expanding scanner coverage without
modifying the core codebase. To prevent supply-chain attacks and tampering,
rule packs can be signed by trusted authors using Ed25519 detached signatures.

By default, the scanner fails closed: unsigned packs are rejected unless
explicitly permitted by configuration or the `--allow-unsigned-packs` flag.

## Pack format and detached signatures

A rule pack consists of:
1. `pack.toml`: The pack manifest describing metadata, compatibility, and rules.
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
- **Bounded execution**: Manifest and payload sizes are capped at 10 MiB to prevent resource exhaustion attacks.
- **Zero secrets**: The scanner only reads and stores public keys. Private signing keys are never required or retained by the scanner.
