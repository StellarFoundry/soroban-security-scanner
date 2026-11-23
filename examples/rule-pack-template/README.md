# Rule Pack Template

A ready-to-copy starter template for authoring Soroban Security Scanner rule packs.
This directory provides a minimal working rule pack following schema v1, complete with
test fixtures, an offline verification script, and documentation.

## Directory Structure

```text
examples/rule-pack-template/
├── pack.toml                 # Schema v1 manifest declaring pack metadata and rules
├── verify.py                 # Offline verification script (Python standard library)
├── README.md                 # This guide
└── fixtures/                 # Positive and negative test fixtures for each rule
    ├── tmpl-001/
    │   ├── positive.rs       # Vulnerable sample: missing admin.require_auth()
    │   └── negative.rs       # Remediated sample: invokes admin.require_auth()
    └── tmpl-002/
        ├── positive.rs       # Vulnerable sample: discarded token transfer result
        └── negative.rs       # Remediated sample: validated token transfer result
```

## Quickstart: Authoring Your Pack

### 1. Copy the Template

Copy this entire directory to your new rule pack repository or workspace:

```bash
cp -r examples/rule-pack-template/ my-soroban-rule-pack/
cd my-soroban-rule-pack/
```

### 2. Customize `pack.toml`

Edit `pack.toml` to specify your pack metadata and rules:

```toml
schema_version = 1

[pack]
name = "my-custom-pack"
version = "0.1.0"
description = "Community rules detecting Soroban protocol risks"
authors = ["Your Name <you@example.com>"]
min_scanner_version = "0.2.0"
capabilities = ["rust_source_analysis"]

[[rules]]
id = "MYPACK-001"
title = "Unchecked admin authorization"
category = "authorization"
default_severity = "high"
default_confidence = "medium"
description = "Flags administrative state modifications that lack caller authorization."
remediation = "Invoke `admin.require_auth()` before modifying protected contract state."
checksum = "sha256:..."
```

### 3. Add Fixtures

For each rule ID defined in `pack.toml`, create a directory under `fixtures/<rule_id_lower>/`:
- `positive.rs`: A contract exhibiting the security vulnerability (expected finding).
- `negative.rs`: A clean or remediated contract where the rule should not flag an issue.

### 4. Compute Canonical Rule Checksums

Rule checksums are cryptographic hashes over canonical JSON serialization of rule metadata
(`id`, `title`, `category`, `default_severity`, `default_confidence`, `description`, and `remediation`).

You can calculate and update all rule checksums in `pack.toml` automatically:

```bash
python verify.py --update-checksums
```

### 5. Validate Offline

Run `verify.py` to ensure schema compliance, rule uniqueness, checksum integrity, and fixture coverage:

```bash
python verify.py
```

Expected output:
```text
OK: validated 2 rules in .../pack.toml
```

### 6. Sign Your Pack (Optional but Recommended)

In production, rule packs can be cryptographically signed using Ed25519 detached signatures:

```bash
# 1. Sign raw bytes of pack.toml (using openssl, python cryptography, or ssh-keygen)
# 2. Write pack.sig alongside pack.toml:
cat <<EOF > pack.sig
version = 1
algorithm = "ed25519"
key_id = "my-trusted-key-id"
signature = "<128 lowercase hex characters>"
EOF
```

See [Rule Pack Signing and Verification](../../docs/rule-pack-signing.md) for full signing details.

### 7. Test with `soroban-scan`

Install and test your local rule pack using the scanner CLI:

```bash
# Install rule pack into local registry
soroban-scan pack install .

# List installed packs
soroban-scan pack list

# Test scanning fixtures with your pack enabled
soroban-scan scan fixtures/tmpl-001/positive.rs --allow-unsigned-packs
```

## Included Starter Rules

| Rule ID | Title | Category | Severity | Confidence | Fixtures |
| ------- | ----- | -------- | -------- | ---------- | -------- |
| `TMPL-001` | Unchecked admin authorization | authorization | high | medium | [`fixtures/tmpl-001/`](fixtures/tmpl-001/) |
| `TMPL-002` | Missing return value check on token transfer | defi | medium | medium | [`fixtures/tmpl-002/`](fixtures/tmpl-002/) |

## Safety and Security

- **Data-Only Manifest**: Rule packs are strictly declarative metadata. They do not execute external scripts, load untrusted binaries, or make network calls.
- **Bounded Inputs**: The scanner enforces strict size limits (10 MiB for `pack.toml`, 16 KiB for `pack.sig`) and denies unknown fields (`#[serde(deny_unknown_fields)]`).
- **No Secrets**: Never store private signing keys or sensitive credentials inside your rule pack repository or distribution artifacts.
