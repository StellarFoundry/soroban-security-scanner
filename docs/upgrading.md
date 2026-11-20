# Upgrading `soroban-scan`

This guide is for users upgrading a released `soroban-scan` installation or the
`soroban-scan-core` crate. It covers what can break, how to check an upgrade
before rolling it out, and how to roll back.

For release timing and support windows see [Releases and support](releases.md).
For the maintainer release checklist see
[Release Process](development/release.md).

## Before you upgrade: dry run

Upgrades are low-risk for a scan that you can rerun, but a detector or rule
change can alter findings and therefore your CI gate. Run this check with the
version you have **before** replacing it, and keep the baseline file:

```bash
soroban-scan version
soroban-scan --version
soroban-scan config validate --config soroban-scan.toml
soroban-scan scan ./contracts --write-baseline /tmp/pre-upgrade-baseline.json --fail-on none
```

`config validate` exits `0` and prints
`configuration is valid (min severity: ..., min confidence: ...)` when the file
is accepted. It exits `2` on an unknown field, unknown rule id, or invalid
value. `--write-baseline` records the findings from the current version; it does
not fail the run for findings.

After installing the new version, run:

```bash
soroban-scan version
soroban-scan config validate --config soroban-scan.toml
soroban-scan scan ./contracts --baseline /tmp/pre-upgrade-baseline.json --fail-on none
```

The second scan compares against the old baseline. Findings that appear are
either new in your code or newly detected by the upgraded scanner; review them
before tightening the gate. Findings that disappear may indicate a fixed false
positive or a detector change. The baseline format is versioned independently
of the tool, so this check survives the upgrade.

If your workflow also keeps JSON reports, regenerate them with the new version
before comparing. `compare` requires a report `schema_version`, and `0.2.0`
reports do not contain that field:

```bash
soroban-scan scan ./contracts --format json --output /tmp/after.json --fail-on none
soroban-scan compare /tmp/after.json /tmp/after-2.json
```

## Supported upgrade paths

The project is pre-1.0, so a minor release may contain breaking changes. The
following table records what is known about released versions. If you are
skipping several minors, read every intervening
[`CHANGELOG.md`](../CHANGELOG.md) section and repeat the dry run after each
version.

| Upgrade | Configuration | Baseline | Report / API |
| ------- | ------------- | -------- | ------------ |
| `0.1.x` → `0.2.x` | No change. Existing files remain valid. | Version `1` in both; no migration. | SS-008 was added, so new findings and a changed rule count are expected. Regenerate JSON reports if you compare them. |
| `0.2.x` → a newer release | New optional fields keep old files valid. Removed or renamed fields are rejected and documented in the changelog. | Check the changelog. A baseline format bump rejects older files. | Check `schema_version`; `compare` rejects an unsupported or missing version. |

The workspace version is in [`Cargo.toml`](../Cargo.toml). Both crates are
released in lockstep and the CLI depends on the matching core version; do not
mix a CLI with a different core version by patching `Cargo.toml` by hand.

## Configuration migrations

Configuration is parsed strictly: unknown fields, unknown rule ids, and unknown
category names are rejected rather than ignored. That is deliberate, because a
typo should not silently disable a check.

1. Validate the existing file:
   `soroban-scan config validate --config soroban-scan.toml`.
2. Inspect the effective values after the upgrade:
   `soroban-scan config show --config soroban-scan.toml`.
3. If a key was renamed or removed, edit the file using the release notes and
   the current [Configuration](configuration.md) reference.
4. Re-run the dry-run scan.

`--no-config` is a diagnostic escape hatch: it ignores discovery and runs with
built-in defaults. Do not use it in CI to hide an invalid configuration; fix the
file instead. `soroban-scan init` refuses to overwrite an existing file unless
`--force` is given, so it will not clobber a migrated configuration by accident.

## Baselines

Baselines are keyed by fingerprint (rule id, scan-relative file, and normalized
evidence), not line numbers. Code movement therefore does not invalidate them.
The file format is versioned with `version = 1` today; an unsupported version is
rejected with a clear error, and a truncated or corrupt baseline fails closed.

- Keep the previous baseline until the upgraded scan has been reviewed.
- If a rule's evidence changes, its fingerprint changes. A finding may then
  appear as new even though the source did not change. Review it and, if it is
  expected, rewrite the baseline with `--write-baseline`.
- Do not edit `version` in a baseline to force it to load in another version.
  The version exists to prevent exactly that.

## Machine-readable reports and the core API

- **JSON reports:** the current development line emits `schema_version: "1"`.
  A report without that field (for example from `0.2.0`) is rejected by
  `compare`; `dashboard` accepts it but shows the data it can read.
- **SARIF:** SARIF 2.1.0 is stable.
- **Configuration:** the schema is still pre-1.0 and validated strictly.
- **`soroban-scan-core`:** the stable surface is listed in
  [`api-stability.md`](api-stability.md). Breaking changes to it require a
  version bump, and CI runs `cargo-semver-checks` against the latest tag. While
  the crate is `0.x`, a breaking change still needs a deliberate version bump;
  `release-type: minor` does not excuse lints that require a major version.

If you embed the core crate, pin an exact version in `Cargo.lock`, run your own
tests against the new version, and read the changelog before bumping. The
`0.x` minor line is not an API-compatibility guarantee.

## Upgrades that are not supported

These are explicitly unsupported. They may appear to work, but no fix or
migration will be provided:

- **Downgrading after a newer baseline format.** A baseline written with a
  higher `version` is rejected by older releases. Keep the old baseline, or
  regenerate it with the older version after reviewing the findings.
- **Downgrading after a newer configuration.** A configuration file containing a
  field, rule id, or category that the older version does not know is rejected.
  Restore the older configuration file; do not delete keys blindly.
- **Downgrading across a report-schema change** and expecting `compare` to read
  the new reports. Regenerate reports with the installed version.
- **Mixing crate versions.** Installing a CLI and pinning a different
  `soroban-scan-core` version is not supported. Use the versions Cargo resolves
  together.
- **Skipping the dry run for a major behavior change.** A new detector can add
  findings; review the baseline diff rather than assuming the old gate still
  represents the same policy.

## Rollback

1. Reinstall the previous version:
   `cargo install soroban-scan-cli --version 0.2.0 --locked --force`.
   With prebuilt archives, keep the previous archive and `SHA256SUMS` until the
   upgrade is accepted, and restore that binary instead.
2. Restore the previous `Cargo.toml`/`Cargo.lock` pin or the previous binary
   path. Verify with `soroban-scan version`.
3. Restore the configuration and baseline files you saved before the upgrade.
4. Re-run `config validate` and a scan with `--fail-on none` to confirm the
   rollback behaves as expected.

Rollback is only reliable if you kept the previous configuration and baseline.
They are ordinary files; copy them outside the repository or into your CI
artifact store before upgrading.

## If an upgrade breaks your gate

Open an issue with the output of `soroban-scan version`, the command you ran,
the affected rule id, and a minimal source example if the code can be shared.
Do not paste secrets or private contract source into a public issue.
