# Rule Pack Authoring Guide

This guide describes how to author, test, sign, and distribute community rule packs for the
Soroban Security Scanner.

Rule packs provide an extensible, declarative mechanism to distribute detection metadata,
remediations, and test fixtures for Soroban smart contracts without modifying scanner core code.
Packs are strictly data-only: they never execute untrusted code, compile binaries, or make network calls.

A ready-to-copy starter template is available in [`examples/rule-pack-template/`](../examples/rule-pack-template/README.md).
A complete two-rule reference example is available in [`examples/external-rule-pack/`](../examples/external-rule-pack/README.md).

---

## Directory Structure

A compliant rule pack adheres to the following directory layout:

```text
my-rule-pack/
├── pack.toml                 # Schema v1 manifest declaring pack metadata and rules (required)
├── pack.sig                  # Detached Ed25519 signature file in TOML format (optional in dev, required in prod)
├── README.md                 # Documentation describing the pack, rules, and author contact
├── verify.py                 # Offline validation script (uses Python standard library)
└── fixtures/                 # Positive and negative test fixtures organized by rule ID
    ├── com-001/
    │   ├── positive.rs       # Contract exhibiting the flaw (vulnerable fixture)
    │   └── negative.rs       # Contract with proper mitigation (clean fixture)
    └── com-002/
        ├── positive.rs
        └── negative.rs
```

### Directory Conventions

- `pack.toml`: The root manifest file.
- `pack.sig`: Placed in the same directory alongside `pack.toml`.
- `fixtures/<rule_id_lower>/`: Fixture directory names must match rule IDs converted to lowercase (e.g. rule `COMM-001` maps to directory `fixtures/comm-001/`). Each directory must contain valid Soroban Rust contracts illustrating both vulnerable (`positive.rs`) and remediated (`negative.rs`) patterns.

---

## Manifest Reference (`pack.toml`)

The manifest uses TOML and adheres to `schema_version = 1`.
The scanner deserializes manifests with strict validation (`#[serde(deny_unknown_fields)]`). Any unrecognized key or schema mismatch causes verification to fail.

### Complete Annotated Manifest

```toml
schema_version = 1

[pack]
name = "soroban-defi-security"
version = "1.0.0"
description = "Community rules detecting common Soroban DeFi vulnerabilities"
authors = ["Security Team <security@example.com>"]
min_scanner_version = "0.2.0"
max_scanner_version = "1.99.99"
capabilities = ["rust_source_analysis"]

[[rules]]
id = "COMM-001"
title = "Unbounded slippage in swap invocation"
category = "defi"
default_severity = "high"
default_confidence = "medium"
description = "Flags swap calls where max_slippage is unconstrained or zero."
remediation = "Require an explicit nonzero slippage bound parameter in the swap call."
checksum = "sha256:41b4971ca5a0aa656406c4e86985de006119bac6a9aa36410eb2038f016c1e61"

[[rules]]
id = "COMM-002"
title = "Missing oracle freshness verification"
category = "oracle"
default_severity = "medium"
default_confidence = "low"
description = "Flags oracle price usage without validating ledger sequence or timestamp."
remediation = "Assert that oracle timestamp is within acceptable tolerance of the current ledger."
checksum = "sha256:0d69485bb042f9b2d28f090d8050e50529d3cfbd0b8527a29653a9254c25608b"
```

### Top-Level Fields

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
| `schema_version` | integer | Yes | Must be integer `1`. Future schemas will increment this version. |

### `[pack]` Table

| Field | Type | Required | Constraints & Description |
| ----- | ---- | -------- | ------------------------- |
| `name` | string | Yes | 1 to 64 lowercase ASCII characters and digits separated by single hyphens (`^[a-z0-9]+(-[a-z0-9]+)*$`). Cannot have consecutive, leading, or trailing hyphens. |
| `version` | string | Yes | Semantic version string (`MAJOR.MINOR.PATCH`). |
| `description` | string | No | Human-readable overview of what the rule pack covers. |
| `authors` | array of strings | No | List of author names and contact information. |
| `min_scanner_version` | string | Yes | Semver lower bound of scanner compatibility. |
| `max_scanner_version` | string | No | Optional semver upper bound of scanner compatibility. Must not precede `min_scanner_version`. |
| `capabilities` | array of strings | Yes | Non-empty list of unique capabilities required by the pack. Currently supported: `rust_source_analysis`, `cargo_manifest_analysis`. |

### `[[rules]]` Table

A pack must define at least one `[[rules]]` entry. Rule IDs must be unique within the manifest.

| Field | Type | Required | Allowed Values & Description |
| ----- | ---- | -------- | ---------------------------- |
| `id` | string | Yes | Upper-case prefix followed by a numeric suffix (e.g. `COMM-001`, `TMPL-001`). Must be unique in the pack. |
| `title` | string | Yes | Non-empty descriptive title summarizing the finding. |
| `category` | string | Yes | Non-empty vulnerability category (e.g. `authorization`, `defi`, `oracle`, `storage`, `arithmetic`). |
| `default_severity` | string | Yes | One of: `critical`, `high`, `medium`, `low`, `informational`. Lowercase only. |
| `default_confidence` | string | Yes | One of: `high`, `medium`, `low`. Lowercase only. |
| `description` | string | Yes | Non-empty explanation of the risk or vulnerability condition. |
| `remediation` | string | No | Guidance on remediating or mitigating the vulnerability. |
| `checksum` | string | Yes | `sha256:` prefix followed by 64 lowercase hex characters representing the SHA-256 digest of the canonical JSON rule payload. |

---

## Canonical Checksum Calculation

Rule checksums ensure integrity and detect accidental corruption or tampering.

### Serialization Specification

The rule checksum is computed as:
$$\text{checksum} = \text{"sha256:"} + \text{hex}(\text{SHA-256}(\text{CanonicalJSON}(\text{rule})))$$

Canonical JSON requires:
1. **Field Selection & Exact Order**:
   - `id` (string)
   - `title` (string)
   - `category` (string)
   - `default_severity` (string, lowercase)
   - `default_confidence` (string, lowercase)
   - `description` (string)
   - `remediation` (string, included **only** when present and non-empty)
2. **Compact Formatting**:
   - Separators must be `(',', ':')` without whitespace.
   - UTF-8 encoding without ASCII escaping (`ensure_ascii=False`).
   - Sorted keys are **not** used; the field sequence above is strictly preserved.

### Python Reference Implementation

```python
import hashlib
import json

CHECKSUM_FIELDS = (
    "id",
    "title",
    "category",
    "default_severity",
    "default_confidence",
    "description",
    "remediation",
)

def compute_rule_checksum(rule: dict) -> str:
    payload = {
        key: rule[key]
        for key in CHECKSUM_FIELDS
        if key in rule and rule[key] is not None
    }
    canonical_bytes = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical_bytes).hexdigest()
```

### Automated Checksum Updates

The `verify.py` script included in `examples/rule-pack-template/` supports automatic calculation and in-place manifest updates:

```bash
python examples/rule-pack-template/verify.py --update-checksums
```

---

## Versioning and Compatibility

Rule packs follow Semantic Versioning (`MAJOR.MINOR.PATCH`):

- **MAJOR** version bumps occur when:
  - Rules are removed or renamed.
  - A rule's semantics change in a breaking manner.
  - Minimum scanner requirements jump across major scanner releases.
- **MINOR** version bumps occur when:
  - New rules or fixtures are added.
  - New capabilities or non-breaking features are introduced.
- **PATCH** version bumps occur when:
  - Typographical or documentation fixes are made.
  - Rule descriptions, titles, or remediations are updated (requiring checksum recalculation).

### Scanner Compatibility Verification

Rule packs are opt-in: they are loaded only when a user explicitly installs one
or a conformance runner opens a pack directory. Before a pack is accepted, the
scanner checks the inclusive compatibility range and capability requirements:

1. `scanner_version >= min_scanner_version`
2. `scanner_version <= max_scanner_version` (if specified)
3. Every capability in `pack.capabilities` must appear in the scanner's
   `SCANNER_CAPABILITIES` list.

The check is shared by `PackLoader` and `soroban-scan pack install/update`. A
pack outside its declared range is rejected with a message naming the current
scanner version and the unsupported bound; a pack requiring an unknown
capability is rejected with the capability name. Compatibility is never
inferred from a pack's own version or from rule text. Manifest size, rule
count, and field validation remain bounded, and no secret or private key is
needed to evaluate compatibility.

---

## Cryptographic Signing (`pack.sig`)

In production environments, rule packs should be cryptographically signed by authoring organizations to guarantee authenticity and prevent tampering.

### The `pack.sig` File

`pack.sig` is a detached TOML signature file stored adjacent to `pack.toml`:

```toml
version = 1
algorithm = "ed25519"
key_id = "stellar-foundry-active"
signature = "7a4b2c...<128 lowercase hex characters>"
```

| Field | Type | Description |
| ----- | ---- | ----------- |
| `version` | integer | Must be integer `1`. |
| `algorithm` | string | Must be `"ed25519"`. |
| `key_id` | string | Identifier matching a key registered in consumer keyring. |
| `signature` | string | 64-byte Ed25519 signature encoded as 128 lowercase hex characters. |

### Signing Instructions

> [!IMPORTANT]
> Always sign the **raw, exact bytes** of `pack.toml`. Do not normalize, re-format, or modify line endings after signing. Any single-byte modification invalidates the signature.

1. **Generate an Ed25519 Keypair**:
   ```bash
   # Generate private key
   openssl genpkey -algorithm ed25519 -out pack_signing_key.pem

   # Derive 32-byte public key (in hex format)
   openssl pkey -in pack_signing_key.pem -pubout -outform DER | tail -c 32 | xxd -p -c 32
   ```

2. **Sign Manifest**:
   ```bash
   openssl pkeyutl -sign -inkey pack_signing_key.pem -rawin -in pack.toml -out pack.sig.bin
   xxd -p -c 64 pack.sig.bin > signature.hex
   ```

3. **Format `pack.sig`**:
   Write the resulting 128 hex characters into `pack.sig` as shown above.

4. **Never Commit Secrets**:
   Private keys must remain secret. Never commit private keys to version control, embed them in CI artifacts, or publish them with the pack.

### Consumer Keyring Configuration

Consumers register trusted public keys in `.soroban-scan.toml` or `soroban-scan.toml`:

```toml
[[packs.trusted_keys]]
key_id = "stellar-foundry-active"
public_key = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
status = "active" # active | retired | revoked
```

- `active`: Key is authorized to sign packs.
- `retired`: Key was valid in the past; existing installed packs remain valid, but new installations or updates fail.
- `revoked`: Key is compromised; all packs signed by this key are immediately rejected.

See [Rule Pack Signing and Verification](rule-pack-signing.md) for full protocol details.

---

## Test Harness and Validation

Rule pack authors must validate packs prior to distribution.

### 1. Offline Validation (`verify.py`)

Run the template's offline verification script:

```bash
python verify.py
```

`verify.py` validates:
- Manifest syntax and schema v1 constraints.
- Pack name regex and version semver syntax.
- Rule ID uniqueness and presence of required fields.
- Canonical JSON checksum equivalence for every rule.
- Presence of corresponding fixture directories under `fixtures/<rule_id_lower>/` with valid `.rs` test contracts.

### 2. Testing in Rust

Authors embedding or testing rule packs in Rust can use the core scanner testing API:

```rust
use std::path::Path;
use soroban_scan_core::pack::{KeyRing, PackManifest, PackVerifier, VerificationPolicy};

// 1. Load and validate manifest structure & checksums
let manifest = PackManifest::load_file(Path::new("path/to/pack.toml"))?;
manifest.validate()?;

// 2. Verify directory (unsigned development mode)
let res = PackVerifier::verify_pack_dir(
    Path::new("path/to/pack-dir"),
    &KeyRing::new(),
    VerificationPolicy::AllowUnsigned,
)?;
```

### 3. CLI Smoke Testing

Authors can test installation, listing, and scanning with the CLI:

```bash
# Install local rule pack into local store
soroban-scan pack install ./my-rule-pack

# Verify pack is registered in the lockfile
soroban-scan pack list

# Scan a test fixture using the pack
soroban-scan scan ./my-rule-pack/fixtures/comm-001/positive.rs --allow-unsigned-packs
```

---

## Security Considerations

Authoring and consuming rule packs enforces strong security boundaries:

1. **Opt-in Verification Policy**: Unsigned packs are rejected by default. Consumers must explicitly supply `--allow-unsigned-packs` during local development or configure trusted signing keys in production.
2. **Declarative Metadata Only**: Rule packs contain metadata only. They cannot execute shell scripts, run binaries, invoke subprocesses, or access the network.
3. **Strict Bounds Checking**:
   - Manifest files are bounded to a maximum of 10 MiB before parsing (`MAX_PACK_MANIFEST_BYTES`).
   - Detached signature files are bounded to a maximum of 16 KiB (`MAX_PACK_SIGNATURE_BYTES`).
   - Manifest parser denies all unknown fields (`#[serde(deny_unknown_fields)]`).
4. **Path Traversal Prevention**: All fixture paths and manifest references must be strictly relative to the pack root. Path traversal (`../`), absolute paths, and symlinks escaping the pack boundary are rejected.
5. **Zero Secret Leakage**: Rule packs must never require or contain private keys, authentication tokens, or credentials.
