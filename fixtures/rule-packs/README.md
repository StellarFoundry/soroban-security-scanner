# Rule pack fixtures

This directory contains fixtures for external rule packs, detached signatures,
cryptographic verification, and the local registry. The sample/pack.toml is an
unsigned schema-v1 metadata sample loaded by the manifest tests.
valid-signed/pack.toml is the signed verification fixture. registry.toml is a
local index fixture referencing valid-signed.

## Layout

    fixtures/rule-packs/
      registry.toml     local index fixture referencing valid-signed
      sample/           unsigned schema-v1 manifest loaded by tests
      valid-signed/     valid pack.toml with a detached pack.sig
      tampered/         pack.toml altered after signing
      unsigned/         pack.toml without a pack.sig
      revoked-key/      pack.toml signed with a revoked key
      untrusted-key/    pack.toml signed with an unknown key

## Security

These fixtures use deterministic test keys with synthetic rule manifests. Real
signing keys and secrets are never committed to the repository.
