# Rule pack CLI

`soroban-scan pack` installs, lists, updates, and removes community rule packs
from a local directory. The commands are opt-in, offline, and bounded. They never
download content, execute pack code, or read signing keys.

## Store layout

The default store is `.soroban-scan/packs` under the current directory. Override
it with `--dir`, placed before the subcommand:

```bash
soroban-scan pack --dir ./vendor/packs install ./my-pack
```

An installed pack is copied to `packs/<name>/` and recorded in
`registry.toml`, the lockfile:

```toml
schema_version = 1

[[packs]]
name = "my-pack"
version = "0.1.0"
checksum = "sha256:<64 lowercase hex digits>"
manifest = "packs/my-pack/pack.toml"
```

`checksum` is the SHA-256 of the exact installed `pack.toml` bytes. Entries are
sorted by name, so the lockfile is byte-identical regardless of install order.
The lockfile is a valid [local registry](rule-pack-registry.md) index and is
validated with `PackRegistry::load` after every write.

Only `pack.toml` and an optional detached `pack.sig` are copied. Other files in
the source directory are ignored; pack code is never executed.

## Commands

```bash
# Install from a directory (or a single pack.toml path).
soroban-scan pack install ./my-pack

# List installed packs from the lockfile.
soroban-scan pack list

# Replace an installed pack with a new local version.
soroban-scan pack update ./my-pack

# Remove a pack. Interactive confirmation is required.
soroban-scan pack uninstall my-pack
# Non-interactive use must opt in explicitly.
soroban-scan pack uninstall my-pack --yes
```

`install` rejects a pack whose name is already installed; use `update`.
`uninstall` refuses to delete anything when the lockfile's manifest path is not
the layout this command creates, and it only removes `packs/<name>/`.

## Limits and safety

- Manifests are limited to 10 MiB; detached signatures to 16 KiB.
- At most 256 packs may be installed.
- A pack manifest must pass `PackManifest::validate`, including rule checksums.
- The lockfile is validated after every write; a malformed lockfile fails closed.
- No environment variables, tokens, or private keys are read or stored.
- Pack signatures are preserved for later verification but are not evaluated by
  these commands. See [Rule pack signing](rule-pack-signing.md).

## Related

- [Local rule pack registry](rule-pack-registry.md)
- [Rule pack signing and verification](rule-pack-signing.md)
- [Rule pack sandboxing](pack-sandboxing.md)
