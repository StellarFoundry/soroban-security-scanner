#!/usr/bin/env python3
"""Validate the example external rule pack offline.

Checks the manifest schema shape, that it contains exactly two rules, that each
rule has a fixture directory, and that every rule checksum matches the canonical
JSON defined by docs/rule-pack-signing.md.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
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
    payload = {key: rule[key] for key in CHECKSUM_FIELDS if key in rule}
    return json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def expected_checksum(rule: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical_rule(rule)).hexdigest()


def main() -> int:
    manifest = tomllib.loads((ROOT / "pack.toml").read_text(encoding="utf-8"))
    problems: list[str] = []

    if manifest.get("schema_version") != 1:
        problems.append("schema_version must be 1")
    rules = manifest.get("rules", [])
    if len(rules) != 2:
        problems.append(f"expected exactly two rules, found {len(rules)}")

    for rule in rules:
        rule_id = rule.get("id", "<missing>")
        expected = expected_checksum(rule)
        if rule.get("checksum") != expected:
            problems.append(
                f"{rule_id}: checksum {rule.get('checksum')!r} != {expected!r}"
            )
        fixture_dir = ROOT / "fixtures" / str(rule_id).lower()
        if not fixture_dir.is_dir():
            problems.append(f"{rule_id}: missing fixture directory {fixture_dir}")
        elif not any(fixture_dir.glob("*.rs")):
            problems.append(f"{rule_id}: no Rust fixtures in {fixture_dir}")

    if problems:
        for problem in problems:
            print(f"FAIL: {problem}")
        return 1
    print(f"OK: validated {len(rules)} rules in {ROOT / 'pack.toml'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
