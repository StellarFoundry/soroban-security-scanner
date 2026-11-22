"""Tests for the example-contract corpus validator."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import check_examples  # noqa: E402

VALID = """// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Require the stored administrator before a write.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn set(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&0, &admin);
    }
}
"""

README = """# Example contract corpus

The corpus currently contains **1** contracts across 1 categories.

| Category | Example |
| -------- | ------- |
| authorization | [admin-auth](authorization/admin-auth.rs) |
"""


class CheckExamplesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.base = self.root / "examples" / "contracts"
        self.base.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, relative: str, content: str) -> Path:
        path = self.base / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def valid_corpus(self) -> None:
        self.write("authorization/admin-auth.rs", VALID)
        self.write("README.md", README)

    def test_valid_corpus_passes(self) -> None:
        self.valid_corpus()
        self.assertEqual(check_examples.validate(self.root, minimum=1), [])

    def test_missing_spdx_header_is_reported(self) -> None:
        self.valid_corpus()
        self.write(
            "authorization/admin-auth.rs",
            VALID.replace("// SPDX-License-Identifier: MIT\n", ""),
        )
        problems = check_examples.validate(self.root, minimum=1)
        self.assertTrue(any("first line" in problem for problem in problems))

    def test_category_must_match_directory(self) -> None:
        self.valid_corpus()
        self.write(
            "authorization/admin-auth.rs",
            VALID.replace("Category: authorization", "Category: storage"),
        )
        problems = check_examples.validate(self.root, minimum=1)
        self.assertTrue(any("does not match directory" in problem for problem in problems))

    def test_missing_focus_and_contract_body_are_reported(self) -> None:
        self.valid_corpus()
        self.write(
            "authorization/admin-auth.rs",
            VALID.replace("//! Focus: Require the stored administrator before a write.\n", "")
            .replace("#[contractimpl]", "// no implementation"),
        )
        problems = check_examples.validate(self.root, minimum=1)
        self.assertTrue(any("Focus" in problem for problem in problems))
        self.assertTrue(any("contractimpl" in problem for problem in problems))

    def test_readme_must_index_every_example(self) -> None:
        self.valid_corpus()
        self.write(
            "README.md",
            README.replace("[admin-auth](authorization/admin-auth.rs)", "admin-auth"),
        )
        problems = check_examples.validate(self.root, minimum=1)
        self.assertTrue(any("not indexed" in problem for problem in problems))

    def test_minimum_count_is_enforced(self) -> None:
        self.valid_corpus()
        problems = check_examples.validate(self.root, minimum=2)
        self.assertTrue(any("at least 2 examples" in problem for problem in problems))

    def test_duplicate_names_are_reported(self) -> None:
        self.valid_corpus()
        self.write("storage/admin-auth.rs", VALID.replace("Category: authorization", "Category: storage"))
        problems = check_examples.validate(self.root, minimum=1)
        self.assertTrue(any("duplicate example name" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
