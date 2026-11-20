# Release Process

## Versioning

This project follows [Semantic Versioning](https://semver.org/). While the
version is `0.x`, minor releases may include breaking changes; they are always
documented in [`CHANGELOG.md`](../../CHANGELOG.md).

## Before releasing

Run the full gate:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --release
cargo run --release -p soroban-scan-core --example benchmark
```

CI must be green, including `cargo-deny` (advisories, licenses, bans, sources).

## Public API checks

The `semver` CI job runs
[`cargo-semver-checks`](https://github.com/obi1kenobi/cargo-semver-checks) for
`soroban-scan-core` on every pull request. It compares the branch against the
latest `v*` tag and skips cleanly when no tag exists yet.

While the workspace version is `0.x`, the job passes `release-type: minor`.
That relaxes the lints a minor release satisfies, but it does **not** relax
lints that require a major version: `cargo-semver-checks` still exits `100`
and reports `Summary semver requires new major version` for those, and the
`Semver (core)` job still fails. A breaking change to the public API of
`soroban-scan-core` therefore needs a deliberate version bump even while the
crate is pre-1.0. Revisit the setting when 1.0 ships. The stable surface is
documented in [`docs/api-stability.md`](../api-stability.md).

## Release checklist

1. Ensure `main` is green in CI.
2. Update `CHANGELOG.md`: move `Unreleased` entries under the new version and
   add the date.
3. Bump `version` in the workspace `Cargo.toml` (`[workspace.package]`).
4. Update `docs/PROJECT_STATUS.md`.
5. Commit with `chore(release): vX.Y.Z`.
6. Create an annotated, signed tag:

   ```bash
   git tag -a vX.Y.Z -m "Soroban Security Scanner vX.Y.Z"
   git push origin main --follow-tags
   ```

7. The `publish.yml` workflow creates or updates the GitHub release from the
   matching `## [X.Y.Z]` section of `CHANGELOG.md`. Preview the body locally
   before tagging:

   ```bash
   python3 tools/release_notes.py --tag vX.Y.Z
   ```

   A missing or empty section fails the `verify` job, so a release can never be
   published with notes that do not exist. To exercise the path on a
   pre-release tag without publishing crates or creating a release, run the
   workflow in dry-run mode against that tag:

   ```bash
   gh workflow run publish.yml --ref vX.Y.Z-rc.1 -f dry_run=true
   ```

8. Verify the release and tag on GitHub.

## Artifacts

Source is the primary artifact, and the tag workflow publishes crate packages in
lockstep. The `binaries` job also builds release archives for
`x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`,
`x86_64-apple-darwin`, `aarch64-apple-darwin`, and
`x86_64-pc-windows-msvc`, writes a `.sha256` file for each archive, and attests
build provenance with GitHub artifact attestations. The `release-assets` job
merges the per-archive checksums into `SHA256SUMS`, verifies it, attests the
merged file, and uploads the archives plus `SHA256SUMS`. A CycloneDX JSON SBOM
is generated with `cargo-cyclonedx` and uploaded to the same release.

Verification commands, including what is and is not signed, are in
[`docs/supply-chain.md`](../supply-chain.md).

## Package publishing

Tag releases publish both crates in lockstep through
`.github/workflows/publish.yml`. The workflow:

1. requires a `v*` tag and verifies it matches `[workspace.package].version`;
2. runs `cargo publish --dry-run` for `soroban-scan-core`;
3. publishes `soroban-scan-core`, waits for the crates.io index to serve that
   version, then runs the CLI dry-run and publishes `soroban-scan-cli`.

The token is a **least-privilege crates.io token** scoped to the two crate names
and stored as the `CARGO_REGISTRY_TOKEN` secret in the protected `crates-io`
environment. Tag pushes publish automatically; `workflow_dispatch` defaults to a
dry run and only publishes when run against a tag with `dry_run` disabled.
`cargo publish --dry-run` also runs on every pull request in the `package` CI
job.

Versions must stay in lockstep: both crates inherit `[workspace.package].version`
and the CLI depends on the exact same core version. Bump the workspace version
once, never the crates independently.

## Post-release

- Announce in the repository discussions.
- Open a fresh `Unreleased` section in the changelog.
