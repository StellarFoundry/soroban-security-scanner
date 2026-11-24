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
```
fixtures/rule-packs/
  valid-signed/          # Valid pack.toml with valid detached pack.sig signed by active key
  tampered/              # pack.toml content altered after signing (signature mismatch)
  unsigned/              # pack.toml without a pack.sig (rejected by default, allowed with opt-in)
  revoked-key/           # pack.toml signed with a revoked key (fails verification)
  untrusted-key/         # pack.toml signed with an unknown key not in the keyring
  conformance-valid/     # Signed conformance fixture pack with contract + conformance.toml known findings
  broken-manifest/       # Malformed pack.toml with unknown fields (fails manifest validation)
  incompatible-version/  # Signed pack requiring scanner >= 99.0.0 (fails compatibility check)
  broken-expectations/   # Signed pack whose conformance.toml expects a non-firing rule (fails clearly)
```

## Security

These fixtures use deterministic test keys with synthetic rule manifests. Real
signing keys and secrets are never committed to the repository.
