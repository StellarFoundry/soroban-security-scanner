"""Tests for the Markdown documentation link checker."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import check_docs  # noqa: E402


class CheckDocsTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, name: str, content: str = "") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def check(self, name: str, content: str) -> list[str]:
        return check_docs.check_file(self.write(name, content), self.root)

    def test_relative_link_to_existing_file_passes(self) -> None:
        self.write("guide.md")
        self.assertEqual(self.check("README.md", "[guide](guide.md)"), [])

    def test_broken_relative_link_is_reported(self) -> None:
        problems = self.check("README.md", "[guide](missing.md)")
        self.assertEqual(len(problems), 1)
        self.assertIn("broken link -> missing.md", problems[0])

    def test_external_anchor_and_mailto_links_are_ignored(self) -> None:
        content = (
            "[web](https://example.com)\n"
            "[mail](mailto:dev@example.com)\n"
            "[local](#section)\n"
        )
        self.assertEqual(self.check("README.md", content), [])

    def test_fragment_is_ignored_when_resolving_the_file(self) -> None:
        self.write("guide.md")
        self.assertEqual(
            self.check("README.md", "[section](guide.md#install)"), []
        )

    def test_nested_links_resolve_from_the_document_directory(self) -> None:
        self.write("README.md")
        self.write("docs/guide.md")
        self.assertEqual(
            self.check("docs/page.md", "[home](../README.md)"), []
        )

    def test_reference_style_links_are_checked(self) -> None:
        self.write("guide.md")
        content = "[guide][docs]\n\n[docs]: guide.md\n"
        self.assertEqual(self.check("README.md", content), [])

    def test_broken_reference_style_links_are_reported(self) -> None:
        content = "[guide][docs]\n\n[docs]: missing.md\n"
        problems = self.check("README.md", content)
        self.assertIn("broken link -> missing.md", problems[0])

    def test_collapsed_reference_uses_the_link_text(self) -> None:
        self.write("guide.md")
        content = "[guide][]\n\n[guide]: guide.md\n"
        self.assertEqual(self.check("README.md", content), [])

    def test_undefined_reference_is_ignored(self) -> None:
        self.assertEqual(self.check("README.md", "[guide][missing]"), [])

    def test_relative_reference_definitions_are_checked_without_usage(self) -> None:
        content = "[unused]: missing.md\n"
        problems = self.check("README.md", content)
        self.assertEqual(len(problems), 1)

    def test_skipped_directories_are_not_scanned(self) -> None:
        self.write("target/generated.md")
        self.write("docs/guide.md")
        found = {
            path.relative_to(self.root).as_posix()
            for path in check_docs.iter_markdown(self.root)
        }
        self.assertEqual(found, {"docs/guide.md"})


if __name__ == "__main__":
    unittest.main()
