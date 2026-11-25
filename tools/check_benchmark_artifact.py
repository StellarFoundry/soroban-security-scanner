#!/usr/bin/env python3
"""Validate a benchmark dashboard artifact produced by `tools/benchmark.py`.

Read-only and offline. Exits non-zero when the artifact is missing, malformed,
references external resources, or leaks an absolute path. The checks are
deliberately strict so CI fails rather than publishing a non-self-contained or
machine-specific dashboard.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = 1
JSON_NAME = "benchmark.json"
HTML_NAME = "index.html"
STATUSES = {"pass", "fail"}
STAT_KEYS = ("runs", "min_ms", "median_ms", "mean_ms", "max_ms")
OPTIONAL_STAT_KEYS = ("p95_ms",)
BASELINE_KEYS = ("median_ms", "threshold_factor", "limit_ms")

SCRIPT_RE = re.compile(r"<script\b", re.IGNORECASE)
EXTERNAL_RE = re.compile(r"https?://|[\"']//", re.IGNORECASE)
ABSOLUTE_PATH_RE = re.compile(
    r"(?:^|[\s\"'=(>])(?:[A-Za-z]:[\\/]|/(?:home|Users|root|tmp|var|opt|mnt|workspace|github|builds)(?:/|\b))"
)


def iter_strings(value):
    """Yield every string (keys and values) in a JSON document."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)


def absolute_path_problems(text: str, source: str) -> list[str]:
    """Return problems for absolute-path-looking text."""
    return [
        f"{source}: absolute path in artifact: {match.group(0)!r}"
        for match in ABSOLUTE_PATH_RE.finditer(text)
    ]


def validate_payload(payload: dict) -> list[str]:
    """Validate the dashboard JSON document."""
    problems: list[str] = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        problems.append(
            f"{JSON_NAME}: unsupported schema_version {payload.get('schema_version')!r}"
        )
    if payload.get("metric") != "median_ms":
        problems.append(f"{JSON_NAME}: only the median_ms metric is supported")

    target = payload.get("target")
    if not isinstance(target, str) or not target:
        problems.append(f"{JSON_NAME}: target must be a non-empty string")
    elif Path(target).is_absolute() or PurePosixPath(target).is_absolute():
        problems.append(f"{JSON_NAME}: target must be repository-relative")

    runner = payload.get("runner")
    if not isinstance(runner, str) or not runner:
        problems.append(f"{JSON_NAME}: runner must be a non-empty string")

    if payload.get("status") not in STATUSES:
        problems.append(f"{JSON_NAME}: status must be one of {sorted(STATUSES)}")

    stats = payload.get("stats")
    if not isinstance(stats, dict):
        problems.append(f"{JSON_NAME}: stats must be an object")
    else:
        if not isinstance(stats.get("runs"), int) or stats.get("runs", 0) < 1:
            problems.append(f"{JSON_NAME}: stats.runs must be a positive integer")
        for key in STAT_KEYS[1:]:
            value = stats.get(key)
            if not isinstance(value, (int, float)) or value < 0:
                problems.append(f"{JSON_NAME}: stats.{key} must be a non-negative number")
        for key in OPTIONAL_STAT_KEYS:
            if key in stats:
                value = stats.get(key)
                if not isinstance(value, (int, float)) or value < 0:
                    problems.append(f"{JSON_NAME}: stats.{key} must be a non-negative number")

    baseline = payload.get("baseline")
    if not isinstance(baseline, dict):
        problems.append(f"{JSON_NAME}: baseline must be an object")
    else:
        for key in BASELINE_KEYS:
            value = baseline.get(key)
            if not isinstance(value, (int, float)) or value <= 0:
                problems.append(f"{JSON_NAME}: baseline.{key} must be a positive number")

    regressions = payload.get("regressions")
    if not isinstance(regressions, list) or not all(
        isinstance(item, str) for item in regressions
    ):
        problems.append(f"{JSON_NAME}: regressions must be a list of strings")
    elif payload.get("status") == "fail" and not regressions:
        problems.append(f"{JSON_NAME}: a failing run must record at least one regression")
    elif payload.get("status") == "pass" and regressions:
        problems.append(f"{JSON_NAME}: a passing run must not record regressions")

    for text in iter_strings(payload):
        problems.extend(absolute_path_problems(text, JSON_NAME))
    return problems


def validate_html(text: str, payload: dict) -> list[str]:
    """Validate the dashboard HTML document."""
    problems: list[str] = []
    if not text.strip():
        problems.append(f"{HTML_NAME}: file is empty")
        return problems
    if SCRIPT_RE.search(text):
        problems.append(f"{HTML_NAME}: scripts are not allowed")
    if EXTERNAL_RE.search(text):
        problems.append(f"{HTML_NAME}: external resources are not allowed")
    problems.extend(absolute_path_problems(text, HTML_NAME))

    target = payload.get("target")
    if isinstance(target, str) and target and target not in text:
        problems.append(f"{HTML_NAME}: does not show the benchmark target")
    median = payload.get("stats", {}).get("median_ms")
    if isinstance(median, (int, float)) and f"{float(median):.1f} ms" not in text:
        problems.append(f"{HTML_NAME}: does not show the median")
    return problems


def check(directory: Path) -> list[str]:
    """Validate a dashboard artifact directory and return all problems."""
    json_path = directory / JSON_NAME
    html_path = directory / HTML_NAME
    problems: list[str] = []
    if not json_path.is_file():
        problems.append(f"{JSON_NAME}: missing from {directory}")
    if not html_path.is_file():
        problems.append(f"{HTML_NAME}: missing from {directory}")
    if problems:
        return problems

    try:
        payload = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{JSON_NAME}: cannot be parsed: {exc}"]
    if not isinstance(payload, dict):
        return [f"{JSON_NAME}: top-level value must be an object"]

    problems.extend(validate_payload(payload))
    try:
        html_text = html_path.read_text(encoding="utf-8")
    except OSError as exc:
        return problems + [f"{HTML_NAME}: cannot be read: {exc}"]
    problems.extend(validate_html(html_text, payload))
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "directory",
        nargs="?",
        default="target/benchmark-dashboard",
        help="dashboard artifact directory (default: target/benchmark-dashboard)",
    )
    args = parser.parse_args()

    problems = check(Path(args.directory))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print(f"OK: benchmark dashboard artifact is valid: {args.directory}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
