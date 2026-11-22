"""CI entry point for the example external rule pack (Issue #369)."""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "examples" / "external-rule-pack" / "verify.py"


class ExternalRulePackTest(unittest.TestCase):
    def test_example_pack_script_validates(self) -> None:
        self.assertTrue(SCRIPT.is_file(), f"missing {SCRIPT}")
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"verify.py failed\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("OK: validated 2 rules", result.stdout)


if __name__ == "__main__":
    unittest.main()
