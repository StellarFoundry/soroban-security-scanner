#!/usr/bin/env python3
"""Validate the published OpenAPI 3.1.0 contract and check for route drift.

Used by CI to verify that ``docs/integration/openapi.json`` is valid JSON,
conforms to OpenAPI 3.1.0, matches the public route table, excludes internal
endpoints, resolves every local ``$ref``, and contains no secret-like strings.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

OPENAPI_VERSION = "3.1.0"
MAX_OPENAPI_BYTES = 256 * 1024

EXPECTED_PUBLIC_ROUTES: tuple[tuple[str, str, str, int], ...] = (
    ("get", "/v1/health", "getHealth", 200),
    ("post", "/v1/scan", "runScan", 200),
    ("post", "/v1/jobs", "submitScanJob", 202),
    ("get", "/v1/jobs/{job_id}", "getScanJob", 200),
    ("get", "/v1/jobs/{job_id}/report", "getScanJobReport", 200),
    ("get", "/v1/rules", "listRules", 200),
    ("get", "/v1/rules/{rule_id}", "getRule", 200),
)

FORBIDDEN_INTERNAL_PREFIXES: tuple[str, ...] = (
    "/internal",
    "/_internal",
    "/debug",
    "/metrics",
)

FORBIDDEN_SECRET_PATTERNS: tuple[str, ...] = (
    "ghp_",
    "github_pat_",
    "sk-",
    "AKIA",
    "-----BEGIN",
    "PRIVATE KEY",
    "secret_key",
    "client_secret",
)


def is_internal_path(path: str) -> bool:
    normalized = path.strip()
    return any(
        normalized == prefix or normalized.startswith(prefix + "/")
        for prefix in FORBIDDEN_INTERNAL_PREFIXES
    )


def _collect_refs(node: object, refs: list[str]) -> None:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str):
            refs.append(ref)
        for value in node.values():
            _collect_refs(value, refs)
    elif isinstance(node, list):
        for item in node:
            _collect_refs(item, refs)


def _resolve_pointer(doc: dict, pointer: str) -> object | None:
    if not pointer.startswith("#/"):
        return None
    current: object = doc
    for part in pointer[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def validate(
    doc: dict,
    expected_routes: tuple[tuple[str, str, str, int], ...] = EXPECTED_PUBLIC_ROUTES,
) -> list[str]:
    """Return a list of validation errors; empty means the contract is valid."""

    problems: list[str] = []
    serialized = json.dumps(doc)
    if len(serialized.encode("utf-8")) > MAX_OPENAPI_BYTES:
        problems.append(f"OpenAPI document exceeds {MAX_OPENAPI_BYTES} bytes")

    for pattern in FORBIDDEN_SECRET_PATTERNS:
        if pattern in serialized:
            problems.append(f"OpenAPI document contains forbidden secret pattern {pattern!r}")

    if doc.get("openapi") != OPENAPI_VERSION:
        problems.append(
            f"expected openapi version {OPENAPI_VERSION!r}, got {doc.get('openapi')!r}"
        )

    info = doc.get("info")
    if not isinstance(info, dict):
        problems.append("missing top-level 'info' object")
    else:
        for key in ("title", "version", "description"):
            val = info.get(key)
            if not isinstance(val, str) or not val.strip():
                problems.append(f"info.{key} must be a non-empty string")

    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        problems.append("missing or empty top-level 'paths' object")
        return problems

    for path_key in paths:
        if is_internal_path(path_key):
            problems.append(f"internal path {path_key!r} must not appear in OpenAPI paths")

    expected_pairs: set[tuple[str, str]] = set()
    for method, path, operation_id, status_code in expected_routes:
        expected_pairs.add((path, method))
        path_item = paths.get(path)
        if not isinstance(path_item, dict):
            problems.append(f"missing public path {path!r}")
            continue
        operation = path_item.get(method)
        if not isinstance(operation, dict):
            problems.append(f"missing method {method!r} on path {path!r}")
            continue
        if operation.get("operationId") != operation_id:
            problems.append(
                f"{method.upper()} {path}: expected operationId {operation_id!r}, "
                f"got {operation.get('operationId')!r}"
            )
        responses = operation.get("responses")
        if not isinstance(responses, dict) or str(status_code) not in responses:
            problems.append(
                f"{method.upper()} {path}: missing expected status {status_code}"
            )

    for path_key, path_item in paths.items():
        if not isinstance(path_item, dict):
            problems.append(f"path {path_key!r} must map to an object")
            continue
        for method_key in path_item:
            if (path_key, method_key) not in expected_pairs:
                problems.append(
                    f"unexpected unimplemented route '{method_key.upper()} {path_key}'"
                )

    refs: list[str] = []
    _collect_refs(doc, refs)
    for ref in refs:
        if not ref.startswith("#/components/") or _resolve_pointer(doc, ref) is None:
            problems.append(f"unresolved $ref {ref!r}")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "openapi",
        nargs="?",
        type=Path,
        default=Path("docs/integration/openapi.json"),
        help="path to the OpenAPI JSON contract (default: docs/integration/openapi.json)",
    )
    args = parser.parse_args()

    try:
        raw = args.openapi.read_text(encoding="utf-8")
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        print(f"error: cannot load {args.openapi}: {error}", file=sys.stderr)
        return 1

    problems = validate(doc)
    if problems:
        print(f"OpenAPI validation failed for {args.openapi}:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    canonical = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if raw.replace("\r\n", "\n") != canonical:
        print(
            f"error: {args.openapi} is not in canonical deterministic format",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {args.openapi} is valid OpenAPI {OPENAPI_VERSION} and matches "
        f"{len(EXPECTED_PUBLIC_ROUTES)} public routes."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
