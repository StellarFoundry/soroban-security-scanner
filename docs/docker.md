# Docker image

The repository includes an **opt-in** `Dockerfile` for running the one-shot CLI
in a container. CI does not publish a registry image; build it locally or in
your own pipeline, pin the result by digest, and push it to a registry you
control. The scanner is a CLI, not a server: there is no listening port, HTTP
API, or long-running process to manage.

## Build

From the repository root:

```bash
docker build --tag soroban-scan:0.2.0 .
```

The first stage compiles the workspace with Rust `1.91.1` and links a static
musl binary. The second stage copies only that binary into `alpine:3.24.4`.
Both bases are pinned by patch tag and digest, so an upstream tag move cannot
silently change the image. Update the digests deliberately when patching bases.

`TARGETARCH` selects the Rust target: `amd64` (default) maps to
`x86_64-unknown-linux-musl` and `arm64` maps to `aarch64-unknown-linux-musl`.
Other values fail the build instead of producing a mismatched binary.

## Entry point and runtime layout

| Setting | Value |
| ------- | ----- |
| Entrypoint | `ENTRYPOINT ["soroban-scan"]` |
| Default command | `scan . --fail-on high` |
| Working directory | `/workspace` (root-owned) |
| User | `65532:65532` (non-root) |
| Health check | `soroban-scan version` |

The entry point means command arguments are scanner arguments, not shell
commands. To override the whole command, use `--entrypoint`.

## Run a scan

Mount the tree to scan read-only and disable networking. A fixture with a known
finding:

```bash
docker run --rm --network none \
  -v "$PWD/fixtures/corpus/SS-001:/src:ro" \
  soroban-scan:0.2.0 scan /src --format json --fail-on none
```

`--fail-on none` keeps the exit code at `0` even when findings are present.
Without it, `--fail-on high` exits `1` when findings meet the threshold; that
is an intended gate, not a container failure. Other useful commands:

```bash
docker run --rm soroban-scan:0.2.0 version
docker run --rm soroban-scan:0.2.0 rules
docker run --rm --network none \
  -v "$PWD/fixtures/projects/soroban-confirmed:/src:ro" \
  soroban-scan:0.2.0 doctor /src --format json
```

To keep a report, mount a writable directory at a path of your choice. The
process runs as UID/GID `65532` and cannot write to `/workspace`, so the host
directory must be writable by that UID (for example, created by a CI job with
`mkdir -p reports && chown 65532:65532 reports`):

```bash
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  -v "$PWD/examples/vulnerable-contract:/src:ro" \
  -v "$PWD/reports:/reports" \
  soroban-scan:0.2.0 scan /src \
    --format json --output /reports/report.json --fail-on none
```

Mount a config file the same way and pass `--config /path/in/container`. The
image contains no config, baseline, fixture, or example source.

## Health check

`HEALTHCHECK CMD ["soroban-scan", "version"]` uses the exec form and runs every
five minutes with a five-second timeout. It proves the binary starts inside the
container; it does **not** validate scan results or rule correctness. A normal
`docker run` exits when the scan finishes, so health checks only run while a
container is kept alive (for example by a wrapper process). For one-shot scans,
use the container exit code and the report as the health signal.

## Security posture

- Non-root by default: `USER 65532:65532`, matching the
  [Kubernetes manifests](kubernetes.md), which also use UID/GID `65532`.
- Nothing is writable by the process at the image root. `/workspace` is owned by
  root; write reports only to an explicitly mounted directory.
- No secrets, tokens, wallets, keys, or `.env` files are copied into the image.
  `.dockerignore` excludes them, and the builder stage copies only the Cargo
  manifests, workspace crates, `xtask`, cargo aliases, and `README.md`.
- No network is needed at scan time; the scanner never downloads code or
  executes the project it scans.
- No image is published or signed by this project. The image is built from the
  pinned source you check out; verify the checkout and the base digests in your
  own supply chain. See [Supply-chain verification](supply-chain.md).

## Validation

CI builds the image and smoke-scans the fixture above in the `docker` job of
`ci.yml`; the structural test checks the pinned bases, non-root user, entry
point, health check, and build context:

```bash
python -m unittest tests.test_dockerfile -v
docker build --tag soroban-scan:local .
docker run --rm --network none -v "$PWD/fixtures/corpus/SS-001:/src:ro" \
  soroban-scan:local scan /src --format json --fail-on none
```

Docker is not required for the Rust test suite or for the rest of CI. The
image is not a substitute for installing the scanner; see
[Installation](installation.md) for local and CI installs without a container.
