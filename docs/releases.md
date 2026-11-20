# Releases and support

This page describes how `soroban-scan` is released, which versions receive
fixes, and what to expect when reporting a security problem. The project is
pre-1.0: these are goals and best-effort commitments, not contractual dates.

The mechanics maintainers follow are in
[Release Process](development/release.md). Upgrade steps are in
[Upgrading](upgrading.md).

## Versioning

Releases follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

While the major version is `0`, a **minor** release may contain breaking
changes. When that happens it is called out in [`CHANGELOG.md`](../CHANGELOG.md)
and the GitHub release notes. Patch releases contain compatible fixes. Rule ids
(`SS-###`) are never reused or renumbered, and documented exit codes do not
change meaning.

The latest published version is the workspace version in
[`Cargo.toml`](../Cargo.toml). At the time of writing it is `0.2.0`
(2026-09-28).

## Release cadence

There is **no fixed release calendar**. A release is cut when:

- reviewed, user-visible changes have accumulated;
- the full local gate and CI are green;
- the changelog has an entry for the version.

A minor release is the normal vehicle for new detectors, commands, and
configuration fields. Patch releases are made for regressions and security
fixes when a maintainer is available. Pre-release tags such as `v0.3.0-rc.1`
may be published for testing; they are not supported releases.

We do not promise a date for `1.0`, for any future feature, or for a release
that is not already funded and in progress. If a date matters to you, track the
issue or ask in the repository discussions rather than relying on this page.

## What a release contains

For every tagged release, the release workflow attempts to publish:

- a GitHub release whose notes come from the matching `CHANGELOG.md` section;
- `soroban-scan-core` and `soroban-scan-cli` on crates.io, in lockstep;
- prebuilt archives for Linux (glibc and musl), macOS (Intel and Apple
  Silicon), and Windows (MSVC);
- a `SHA256SUMS` file covering those archives;
- a CycloneDX JSON SBOM (`soroban-scan.cdx.json`);
- GitHub build-provenance attestations for the archives and `SHA256SUMS`.

How to verify an artifact is covered in [Supply chain](supply-chain.md). If a
release is missing an artifact, that is a defect; open an issue rather than
assuming the artifact exists.

## Support windows

| Version line | Status | Security fixes |
| ------------ | ------ | -------------- |
| Latest released `0.x` minor (currently `0.2.x`) | Supported | Best effort; critical fixes targeted within 30 calendar days |
| Older `0.x` minor lines (for example `0.1.x`) | Unsupported | Not backported by default |
| `main` between releases | Development | Not a supported release |
| Pre-release tags (`-rc`, `-beta`) | Testing only | Not supported |

There is no long-term-support (LTS) line before `1.0`. If you need a fix on an
older line, open an issue and say why; a backport is at the maintainers'
discretion and may be declined when it would require supporting a release that
has no active users.

Non-security bug fixes normally land on `main` and ship in the next release.
They are not backported to older minors unless a maintainer decides the fix is
important enough.

## Security response targets

Security reports are handled through [`SECURITY.md`](../SECURITY.md), never a
public issue. The targets below are best effort and depend on maintainer
availability:

- **Acknowledgement:** within 5 business days.
- **Triage and initial assessment:** within 10 business days.
- **Critical fix:** targeted within 30 calendar days of triage. Complex issues
  may take longer; we will tell you if the target slips.
- **Coordinated disclosure:** a timeline agreed with the reporter. We will not
  publish details before that date without consent.

These targets are goals, not a warranty. A report is not a support contract,
and no response-time service-level agreement is offered.

## Deprecations

Because configuration uses `deny_unknown_fields`, removing or renaming a
configuration key is a breaking change; it does not silently pass. Deprecations
are announced as follows:

1. The change is described in the `CHANGELOG.md` entry for the release that
   introduces the replacement.
2. The GitHub release notes repeat it.
3. Where practical, the old form keeps working for at least one minor release
   before removal, and the replacement is documented in the same change.
4. A removed rule keeps its `SS-###` identifier permanently, even though it no
   longer runs. Rule ids are never reassigned to a different check.

There is no runtime deprecation warning mechanism today: an unknown
configuration field or rule id is rejected when the configuration loads. Treat
the changelog and release notes as the authoritative deprecation notice.

## Asking for support

- Bug reports and feature requests: open a GitHub issue using the templates.
- Security problems: follow [`SECURITY.md`](../SECURITY.md).
- Questions about a specific version: include the output of
  `soroban-scan version` and the exact command you ran.
