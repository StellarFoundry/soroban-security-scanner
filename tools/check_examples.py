#!/usr/bin/env python3
"""Validate the documented example-contract corpus.

Read-only and offline. Every ``examples/contracts/<category>/*.rs`` file must be
MIT licensed, carry its category and focus in the header, contain a contract
implementation, and stay small. The README must index every example. Contracts
are never compiled or executed.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MIN_EXAMPLES = 50
MAX_FILES_BYTES = 8192
MAX_LINES = 120
SPDX = "// SPDX-License-Identifier: MIT"
CATEGORY_RE = re.compile(r"^//! Category: (\S+)\s*$", re.MULTILINE)
FOCUS_RE = re.compile(r"^//! Focus: (.+)$", re.MULTILINE)
KEBAB_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
COUNT_RE = re.compile(r"contains \*\*(\d+)\*\* contracts")


def validate(root: Path, minimum: int = MIN_EXAMPLES) -> list[str]:
    base = root / "examples" / "contracts"
    if not base.is_dir():
        return [f"{base}: example corpus directory is missing"]

    categories = sorted(
        entry.name
        for entry in base.iterdir()
        if entry.is_dir() and entry.name != "__pycache__"
    )
    problems: list[str] = []
    files = sorted(base.glob("*/*.rs"))
    seen: set[str] = set()

    for path in files:
        relative = path.relative_to(base)
        if len(relative.parts) != 2:
            problems.append(f"{relative}: examples must be directly under a category")
            continue
        category = relative.parts[0]
        if category not in categories:
            problems.append(f"{relative}: unknown category directory {category!r}")
        stem = path.stem
        if not KEBAB_RE.match(stem):
            problems.append(f"{relative}: file stem must be kebab-case")
        if stem in seen:
            problems.append(f"{relative}: duplicate example name {stem!r}")
        seen.add(stem)

        text = path.read_text(encoding="utf-8", errors="replace")
        if not text.startswith(SPDX + "\n"):
            problems.append(f"{relative}: first line must be {SPDX!r}")
        match = CATEGORY_RE.search(text)
        if match is None:
            problems.append(f"{relative}: missing '//! Category: <category>' header")
        elif match.group(1) != category:
            problems.append(
                f"{relative}: header category {match.group(1)!r} does not match directory {category!r}"
            )
        focus = FOCUS_RE.search(text)
        if focus is None or not focus.group(1).strip():
            problems.append(f"{relative}: missing non-empty '//! Focus:' header")
        if "#[contractimpl]" not in text:
            problems.append(f"{relative}: missing #[contractimpl] contract body")
        if len(text.encode("utf-8")) > MAX_FILES_BYTES:
            problems.append(f"{relative}: exceeds {MAX_FILES_BYTES} bytes")
        if text.count("\n") > MAX_LINES:
            problems.append(f"{relative}: exceeds {MAX_LINES} lines")

    if len(files) < minimum:
        problems.append(f"expected at least {minimum} examples, found {len(files)}")

    readme = base / "README.md"
    if not readme.is_file():
        problems.append(f"{readme}: missing corpus README")
    else:
        readme_text = readme.read_text(encoding="utf-8", errors="replace")
        listed = set(re.findall(r"\]\(([a-z0-9-]+/[a-z0-9-]+\.rs)\)", readme_text))
        indexed = {path.relative_to(base).as_posix() for path in files}
        for missing in sorted(indexed - listed):
            problems.append(f"README.md: example {missing} is not indexed")
        for stale in sorted(listed - indexed):
            problems.append(f"README.md: index entry {stale} has no file")
        count = COUNT_RE.search(readme_text)
        if count is None:
            problems.append("README.md: missing 'contains **N** contracts' statement")
        elif int(count.group(1)) != len(files):
            problems.append(
                f"README.md: states {count.group(1)} contracts but {len(files)} exist"
            )

    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of tools/)",
    )
    parser.add_argument("--minimum", type=int, default=MIN_EXAMPLES)
    args = parser.parse_args()
    root = args.root.resolve()
    problems = validate(root, args.minimum)

    if problems:
        print(f"Found {len(problems)} example corpus problem(s):")
        for problem in problems:
            print(f"  {problem}")
        return 1

    base = root / "examples" / "contracts"
    files = list(base.glob("*/*.rs"))
    categories = {path.parent.name for path in files}
    print(f"OK: validated {len(files)} example contracts in {len(categories)} categories.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
