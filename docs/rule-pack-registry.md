# Local Rule Pack Registry

The scanner can discover installed community packs from a local `registry.toml` index. Loading an index is offline: it does not fetch remote content or execute pack code. The registry validates its schema, every entry, and each referenced manifest before exposing any entry.

## Index format

The index is UTF-8 TOML, limited to 1 MiB, and uses schema version 1:

```toml
schema_version = 1

[[packs]]
name = "soroban-defi-rules"
version = "0.1.0"
checksum = "sha256:<64 lowercase hex digits>"
manifest = "packs/soroban-defi/pack.toml"
```

`manifest` is a relative path under the directory containing `registry.toml`. Absolute paths, parent-directory traversal, and symlinks that resolve outside that directory are rejected. Referenced manifests are limited to 10 MiB. `checksum` is SHA-256 of the exact manifest bytes, prefixed with `sha256:`. The referenced pack manifest must parse and its name and version must match the index entry. Duplicate name/version pairs and unknown fields are rejected.

Use `PackRegistry::load(path)` to load the index. `entries()` returns validated entries in name/version order, `find(name, version)` looks up an exact release, and `manifest_path(name, version)` returns its local manifest path. An invalid entry rejects the entire index; callers never receive a partially validated registry.

The sample local index is `fixtures/rule-packs/registry.toml`; registry behavior is covered by:

```bash
cargo test -p soroban-scan-core --test pack_registry
```
