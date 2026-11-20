# Installation

## Supported platforms

- Linux, macOS, and Windows.
- A recent stable Rust toolchain. CI builds and tests on stable.

## From source

```bash
git clone https://github.com/AyinkxLab/soroban-security-scanner
cd soroban-security-scanner
cargo build --release -p soroban-scan-cli
```

The binary is written to `target/release/soroban-scan` (`.exe` on Windows).

## Install with Cargo

From a local checkout:

```bash
cargo install --path crates/soroban-scan-cli
```

Once the crates are published, install from crates.io instead:

```bash
cargo install soroban-scan-cli
```

Both commands place `soroban-scan` on your Cargo bin path (usually
`~/.cargo/bin`). `soroban-scan-core` is published in lockstep and installed
automatically as the CLI's dependency.

## Prebuilt binaries

Tagged releases attach prebuilt archives for:

| Platform | Target |
| --- | --- |
| Linux (glibc) | `x86_64-unknown-linux-gnu` |
| Linux (static musl) | `x86_64-unknown-linux-musl` |
| macOS (Intel) | `x86_64-apple-darwin` |
| macOS (Apple Silicon) | `aarch64-apple-darwin` |
| Windows | `x86_64-pc-windows-msvc` |

Download `soroban-scan-<target>.tar.gz` (`.zip` on Windows) and `SHA256SUMS`
from the release, then verify before extracting:

```bash
sha256sum --check --ignore-missing SHA256SUMS
```

Release archives are built by CI from the tagged commit and carry a build
provenance attestation:

```bash
gh attestation verify soroban-scan-x86_64-unknown-linux-gnu.tar.gz \
  --repo AyinkxLab/soroban-security-scanner
```

The attestation proves which workflow and commit produced the digest; it is not
a detached GPG signature. See [Supply-chain verification](supply-chain.md) for
the exact checksum commands per platform, what is attested, and what is not.

## Verify the installation

```bash
soroban-scan version
soroban-scan rules
```

## Windows notes

Either the MSVC or GNU toolchain works. If building with MSVC fails with
`linker link.exe not found`, install the Visual Studio C++ Build Tools, or use
the GNU toolchain with MinGW:

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup override set stable-x86_64-pc-windows-gnu
```

See [Troubleshooting](troubleshooting.md) if you hit other issues.

## Uninstall

- From source: delete the checkout.
- From Cargo: `cargo uninstall soroban-scan-cli`.
