# Contributing to Soroban Security Scanner

Thanks for your interest in improving Soroban security. This document explains
how to contribute effectively.

## Code of Conduct

By participating, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Governance

Roles, the ADR process, and how contentious changes are decided are described
in [`GOVERNANCE.md`](GOVERNANCE.md).

## Ways to contribute

- **Report a bug** — open an issue using the bug report template.
- **Request a feature** — open an issue using the feature request template.
- **Propose or add a security rule** — see [`docs/rules/README.md`](docs/rules/README.md).
- **Add fixtures** — positive/negative examples under `fixtures/`.
- **Improve documentation**.
- **Report a vulnerability** — follow [`SECURITY.md`](SECURITY.md), **not** a public issue.

## Contributing through a wave

If you are contributing through an open-source wave:

- **Request assignment on an issue before starting.** Do not open a pull request
  for an issue you have not been assigned.
- Each issue has a `difficulty/*` label that maps to wave points
  (trivial 100 / medium 150 / high 200).
- Your pull request must include `Closes #<issue-number>`.
- Maintainers respond to new issues and pull requests within 48 hours and give a
  review decision within 72 hours.

See [`docs/WAVE.md`](docs/WAVE.md) for the full process.

## Development setup

See [`docs/development/setup.md`](docs/development/setup.md).

Quick start:

```bash
git clone https://github.com/AyinkxLab/soroban-security-scanner
cd soroban-security-scanner
cargo build
cargo test
```

## Before you open a pull request

Run the full local gate and make sure it passes:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
```

On Windows, this project is developed against both the MSVC and GNU toolchains;
either is acceptable as long as CI passes.

## Pull request expectations

- Keep changes focused; one logical change per pull request where practical.
- Add tests for new behavior. Security-sensitive code requires adversarial tests.
- Update documentation and `CHANGELOG.md` when user-visible behavior changes.
- Never commit secrets, credentials, private keys, or generated build artifacts.
- Describe the **problem**, the **change**, and how you **verified** it.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scanner): add Soroban project detection
fix(rules): avoid false positive for require_auth in helper calls
docs(contributing): document security rule development
test(rules): add authorization regression fixtures
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`,
`chore`, `security`.

## Adding a security rule

Every rule must include:

1. A clear definition of the security problem.
2. The detectable evidence (and, importantly, what is **not** detectable).
3. Known false-positive cases.
4. A positive fixture and a negative fixture.
5. Unit and regression tests.
6. Documentation and remediation guidance.
7. An honest `severity` and `confidence` rating.

Rules must never fabricate findings or source locations. Conservative
`confidence` is preferred over optimistic `confidence`.

## Adding dependencies

Dependencies must satisfy [ADR-0005](docs/architecture/adr/0005-dependency-justification-policy.md).
In the pull request, state what the crate does, why an existing dependency or
the standard library is insufficient, the transitive footprint, and any disabled
features. `cargo deny check` must pass, and a `deny.toml` exception requires a
reviewed justification in the same change.

## Definition of done

- [ ] Code compiles with `clippy -D warnings`.
- [ ] `cargo fmt` is clean.
- [ ] Tests added and pass.
- [ ] Documentation updated.
- [ ] `CHANGELOG.md` updated for user-visible changes.
- [ ] No secrets or credentials committed.

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
