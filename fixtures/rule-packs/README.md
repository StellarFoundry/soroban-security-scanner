# Rule pack fixtures

This directory contains test fixtures for external rule packs, detached signatures,
and cryptographic verification.
The `sample/pack.toml` is an unsigned schema-v1 metadata sample loaded by the
manifest tests. `valid-signed/pack.toml` is the signed verification fixture.

## Layout

```
fixtures/rule-packs/
  sample/           # Unsigned schema-v1 manifest loaded by tests
  valid-signed/     # Valid pack.toml with valid detached pack.sig signed by active key
  tampered/         # pack.toml content altered after signing (signature mismatch)
  unsigned/         # pack.toml without a pack.sig (rejected by default, allowed with opt-in)
  revoked-key/      # pack.toml signed with a revoked key (fails verification)
  untrusted-key/    # pack.toml signed with an unknown key not in the keyring
```

## Security

These fixtures use deterministic test keys with synthetic rule manifests. Real signing
keys and secrets are never committed to the repository.
