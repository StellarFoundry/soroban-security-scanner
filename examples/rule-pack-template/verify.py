#!/usr/bin/env python3
"""Validate the rule pack template offline.

Checks manifest schema v1 compliance, pack metadata, rule field definitions,
canonical JSON checksums (defined in docs/pack-authoring.md and docs/rule-pack-signing.md),
and verifies that positive and negative fixtures exist for every rule.

Supports --update-checksums to recalculate and update checksums in pack.toml.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# Use tomllib from standard library (Python 3.11+)
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

PACK_NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")
VALID_CAPABILITIES = {"rust_source_analysis", "cargo_manifest_analysis"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "informational"}
VALID_CONFIDENCES = {"high", "medium", "low"}

CHECKSUM_FIELDS = (
    "id",
    "title",
    "category",
    "default_severity",
    "default_confidence",
    "description",
    "remediation",
)


def canonical_rule(rule: dict) -> bytes:
    """Serialize rule metadata into canonical compact JSON bytes for checksumming."""
    payload = {key: rule[key] for key in CHECKSUM_FIELDS if key in rule and rule[key] is not None}
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def expected_checksum(rule: dict) -> str:
    """Compute sha256 checksum over canonical rule JSON."""
    return "sha256:" + hashlib.sha256(canonical_rule(rule)).hexdigest()


def validate_pack(pack_dir: Path) -> tuple[list[str], int]:
    """Validate a pack directory offline. Returns (list_of_errors, rule_count)."""
    manifest_path = pack_dir / "pack.toml"
    if not manifest_path.is_file():
        return [f"missing manifest at {manifest_path}"], 0

    try:
        raw_text = manifest_path.read_text(encoding="utf-8")
        manifest = tomllib.loads(raw_text)
    except Exception as exc:
        return [f"failed to parse TOML at {manifest_path}: {exc}"], 0

    problems: list[str] = []

    if manifest.get("schema_version") != 1:
        problems.append("schema_version must be 1")

    pack = manifest.get("pack")
    if not isinstance(pack, dict):
        problems.append("missing [pack] table")
    else:
        name = pack.get("name", "")
        if not PACK_NAME_RE.match(name) or len(name) > 64:
            problems.append(
                f"pack.name '{name}' is invalid; must be 1-64 lowercase ASCII alphanumeric with single hyphens"
            )
        version = pack.get("version", "")
        if not SEMVER_RE.match(version):
            problems.append(f"pack.version '{version}' is not valid semver")
        min_ver = pack.get("min_scanner_version", "")
        if not SEMVER_RE.match(min_ver):
            problems.append(f"pack.min_scanner_version '{min_ver}' is not valid semver")
        max_ver = pack.get("max_scanner_version")
        if max_ver is not None and not SEMVER_RE.match(max_ver):
            problems.append(f"pack.max_scanner_version '{max_ver}' is not valid semver")

        capabilities = pack.get("capabilities", [])
        if not isinstance(capabilities, list) or not capabilities:
            problems.append("pack.capabilities must be a non-empty array")
        else:
            for cap in capabilities:
                if cap not in VALID_CAPABILITIES:
                    problems.append(f"unknown capability '{cap}'")
            if len(capabilities) != len(set(capabilities)):
                problems.append("pack.capabilities must not contain duplicates")

    rules = manifest.get("rules", [])
    if not isinstance(rules, list) or not rules:
        problems.append("pack must contain at least one [[rules]] definition")
        return problems, 0

    seen_ids: set[str] = set()
    for rule in rules:
        rule_id = rule.get("id", "")
        if not rule_id or not isinstance(rule_id, str):
            problems.append("rule missing non-empty 'id'")
            continue
        if rule_id in seen_ids:
            problems.append(f"duplicate rule id '{rule_id}'")
        seen_ids.add(rule_id)

        # Check required string fields
        for field in ("title", "category", "description"):
            val = rule.get(field)
            if not val or not isinstance(val, str) or not val.strip():
                problems.append(f"{rule_id}: field '{field}' must be a non-empty string")

        sev = rule.get("default_severity")
        if sev not in VALID_SEVERITIES:
            problems.append(f"{rule_id}: invalid default_severity '{sev}'")

        conf = rule.get("default_confidence")
        if conf not in VALID_CONFIDENCES:
            problems.append(f"{rule_id}: invalid default_confidence '{conf}'")

        expected = expected_checksum(rule)
        actual = rule.get("checksum")
        if actual != expected:
            problems.append(
                f"{rule_id}: checksum mismatch: actual {actual!r} != expected {expected!r}"
            )

        # Check fixtures
        fixture_dir = pack_dir / "fixtures" / rule_id.lower()
        if not fixture_dir.is_dir():
            problems.append(f"{rule_id}: missing fixture directory {fixture_dir}")
        else:
            rust_fixtures = list(fixture_dir.glob("*.rs"))
            if not rust_fixtures:
                problems.append(f"{rule_id}: no Rust fixtures (*.rs) in {fixture_dir}")
            positive = fixture_dir / "positive.rs"
            negative = fixture_dir / "negative.rs"
            if not positive.is_file() and not negative.is_file() and not rust_fixtures:
                problems.append(f"{rule_id}: expected positive.rs or negative.rs in {fixture_dir}")

    return problems, len(rules)


def update_checksums(pack_dir: Path) -> int:
    """Compute and update checksums in pack.toml."""
    manifest_path = pack_dir / "pack.toml"
    if not manifest_path.is_file():
        print(f"Error: manifest not found at {manifest_path}", file=sys.stderr)
        return 1

    content = manifest_path.read_text(encoding="utf-8")
    manifest = tomllib.loads(content)
    rules = manifest.get("rules", [])
    if not rules:
        print("No rules found in manifest.", file=sys.stderr)
        return 1

    updated_content = content
    for rule in rules:
        rule_id = rule.get("id")
        old_sum = rule.get("checksum", "")
        new_sum = expected_checksum(rule)
        if old_sum != new_sum:
            print(f"Updating {rule_id}: {old_sum} -> {new_sum}")
            if old_sum:
                updated_content = updated_content.replace(f'checksum = "{old_sum}"', f'checksum = "{new_sum}"')
            else:
                print(f"Warning: {rule_id} did not have a checksum line to replace. Please add manually.")

    manifest_path.write_text(updated_content, encoding="utf-8")
    print(f"Successfully updated checksums in {manifest_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate rule pack offline.")
    parser.add_argument(
        "--pack-dir",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="Path to rule pack directory (default: directory of verify.py)",
    )
    parser.add_argument(
        "--update-checksums",
        action="store_true",
        help="Calculate and write expected checksums into pack.toml",
    )
    args = parser.parse_args()

    pack_dir = args.pack_dir.resolve()
    if args.update_checksums:
        return update_checksums(pack_dir)

    problems, rule_count = validate_pack(pack_dir)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1

    print(f"OK: validated {rule_count} rules in {pack_dir / 'pack.toml'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
