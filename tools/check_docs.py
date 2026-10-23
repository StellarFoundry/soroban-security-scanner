#!/usr/bin/env python3
"""Check relative Markdown links in the repository.

Read-only and offline. Exits non-zero when a relative link points to a missing
file. External URLs are not fetched.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
# Reference-style links: [text][label] and collapsed [text][].
REFERENCE_LINK_RE = re.compile(r"\[([^\]]*)\]\[([^\]]*)\]")
# Reference definitions: [label]: target (an optional title is ignored).
REFERENCE_DEF_RE = re.compile(r"^ {0,3}\[([^\]]+)\]:\s*(\S+)", re.MULTILINE)
SKIP_DIRS = {".git", "target", "node_modules", "vendor"}


def iter_markdown(root: Path):
    for path in root.rglob("*.md"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def is_external(target: str) -> bool:
    return (
        target.startswith("http://")
        or target.startswith("https://")
        or target.startswith("mailto:")
        or target.startswith("#")
        or target.startswith("<")
    )


def check_target(raw: str, path: Path, root: Path) -> str | None:
    raw = raw.strip()
    if not raw or is_external(raw):
        return None
    target = raw.split("#", 1)[0].strip()
    if not target:
        return None
    resolved = (path.parent / target).resolve()
    if not resolved.exists():
        return f"{path.relative_to(root)}: broken link -> {raw}"
    return None


def reference_definitions(text: str) -> dict[str, str]:
    """Map lowercase reference labels to their targets."""
    return {
        label.strip().lower(): target
        for label, target in REFERENCE_DEF_RE.findall(text)
    }


def link_targets(text: str) -> list[str]:
    """Return every inline and reference-style link target in a document."""
    targets = [match.group(1) for match in LINK_RE.finditer(text)]

    definitions = reference_definitions(text)
    # Definitions are links too, so check relative targets even when the label
    # is never referenced.
    targets.extend(definitions.values())

    for match in REFERENCE_LINK_RE.finditer(text):
        text_label, reference_label = match.groups()
        label = (reference_label or text_label).strip().lower()
        target = definitions.get(label)
        if target is not None:
            targets.append(target)

    return targets


def check_file(path: Path, root: Path) -> list[str]:
    problems: list[str] = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for raw in link_targets(text):
        problem = check_target(raw, path, root)
        if problem is not None:
            problems.append(problem)
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root (default: parent of tools/)",
    )
    args = parser.parse_args()
    root = args.root.resolve()

    problems: list[str] = []
    count = 0
    for path in iter_markdown(root):
        count += 1
        problems.extend(check_file(path, root))

    if problems:
        print(f"Found {len(problems)} broken link(s) across {count} files:")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print(f"OK: checked {count} Markdown files, no broken relative links.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
