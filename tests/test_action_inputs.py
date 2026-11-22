"""Checks that the composite Action validates its documented inputs.

The Action is a shell composite, so these tests assert on the declared
metadata rather than executing the scanner build.
"""

import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class ActionInputValidationTest(unittest.TestCase):
    def setUp(self):
        self.action = (ROOT / "action.yml").read_text(encoding="utf-8")

    def test_action_validates_documented_formats_and_thresholds(self):
        for value in ("terminal", "json", "sarif", "markdown", "github"):
            self.assertIn(value, self.action)
        for value in ("none", "info", "low", "medium", "high", "critical"):
            self.assertIn(value, self.action)
        self.assertIn("::error title=Invalid action input::", self.action)

    def test_path_and_files_from_are_mutually_exclusive(self):
        self.assertIn("path and files-from are mutually exclusive", self.action)

    def test_documented_inputs_match_action_metadata(self):
        for name in ("path", "format", "output", "fail-on", "baseline", "files-from", "args"):
            self.assertIn(f"  {name}:", self.action)


if __name__ == "__main__":
    unittest.main()
