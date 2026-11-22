# Rule pack moderation

Community rule packs extend the scanner without changing its core. Because a
pack can change which findings a project sees, the registry needs a published
policy for unsafe or malicious packs. This page defines the review criteria,
how to report a problem, and how a pack is removed.

## Principles

- **No endorsement without review.** Listing a pack means "available", not
  "audited" or "endorsed". Registry metadata must never imply that a pack has
  been reviewed unless it has.
- **Fail closed.** When in doubt, a pack is withheld until the reporter and the
  maintainers have enough information to decide.
- **Transparency.** Removals are recorded in `CHANGELOG.md` with the reason and
  the replacement, if any.

## Review criteria

A pack is eligible for the community registry only when:

1. Its manifest validates and its rule checksums match (`PackManifest::validate`).
2. Its signature verifies against a trusted, non-revoked key when signed packs
   are required (`PackVerifier::verify_pack_dir`).
3. It declares only supported capabilities and does not claim execution,
   filesystem, or network permissions.
4. Its rules have stable, unique `SS-###` identifiers, non-empty titles,
   descriptions, and remediation text.
5. Its documentation names the author and the rules' intent, and does not
   claim endorsement.
6. It is bounded: rule count and manifest size stay within the limits enforced
   by the registry and the [sandbox](pack-sandboxing.md).

## Reporting a pack

Report an unsafe, malicious, or broken pack privately using the process in
[`SECURITY.md`](../SECURITY.md). Do not open a public issue for an active
exploit. Include the pack name and version, a description of the behaviour,
and reproduction steps. The security contact is the same as for the scanner
itself.

## Removal path

1. A maintainer confirms the report and opens a private tracking issue.
2. The pack entry is removed from the registry index, or its signing key is
   revoked, so new installs cannot resolve it.
3. The scanner continues to fail closed if the pack is required but can no
   longer be verified.
4. The removal and its reason are recorded in `CHANGELOG.md`. A public note is
   added once coordinated disclosure is complete.

Removing a pack does not delete copies that users already fetched; users are
expected to update their registries. Revoking the signing key is the durable
way to stop trust in the pack.

## Related

- [Rule pack registry](rule-pack-registry.md)
- [Rule pack signing and verification](rule-pack-signing.md)
- [Rule pack sandboxing](pack-sandboxing.md)
- [Security policy](../SECURITY.md)
