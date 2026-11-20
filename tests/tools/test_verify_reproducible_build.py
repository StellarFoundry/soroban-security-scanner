"""Tests for the reproducible-build verification helper."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))

import verify_reproducible_build as repro  # noqa: E402


class HelpersTests(unittest.TestCase):
    def test_sha256_bytes_matches_known_vector(self):
        self.assertEqual(
            repro.sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_parse_host_reads_the_rustc_host(self):
        toolchain = "rustc 1.80.0\nbinary: rustc\nhost: x86_64-pc-windows-msvc\n"
        self.assertEqual(repro.parse_host(toolchain), "x86_64-pc-windows-msvc")
        self.assertIsNone(repro.parse_host("rustc 1.80.0\n"))

    def test_binary_name_uses_exe_only_on_windows(self):
        self.assertEqual(repro.binary_name("soroban-scan", "x86_64-pc-windows-msvc"), "soroban-scan.exe")
        self.assertEqual(repro.binary_name("soroban-scan", "x86_64-unknown-linux-gnu"), "soroban-scan")

    def test_binary_path_is_under_release(self):
        path = repro.binary_path(Path("target"), "soroban-scan", "x86_64-unknown-linux-gnu")
        self.assertEqual(path, Path("target") / "release" / "soroban-scan")

    def test_mismatch_explains_likely_causes(self):
        hints = repro.explain_mismatch()
        self.assertGreaterEqual(len(hints), 3)
        self.assertTrue(any("toolchain" in hint for hint in hints))

    def test_parse_env_accepts_key_value_pairs(self):
        self.assertEqual(repro.parse_env(["RUSTFLAGS=-Cdebuginfo=0"]), {"RUSTFLAGS": "-Cdebuginfo=0"})

    def test_parse_env_rejects_malformed_values(self):
        with self.assertRaises(Exception):
            repro.parse_env(["NO_EQUALS"])
        with self.assertRaises(Exception):
            repro.parse_env(["=value"])

    def test_render_reports_match_and_mismatch(self):
        report = {
            "package": "soroban-scan",
            "manifest": "Cargo.toml",
            "toolchain": {
                "rustc": "rustc 1.80.0\nhost: x86_64-unknown-linux-gnu",
                "cargo": "cargo 1.80.0",
                "host": "x86_64-unknown-linux-gnu",
            },
            "environment": {"SOURCE_DATE_EPOCH": "0"},
            "builds": [
                {"attempt": 1, "sha256": "a" * 64, "bytes": 10},
                {"attempt": 2, "sha256": "a" * 64, "bytes": 10},
            ],
            "reproducible": True,
        }
        text = repro.render_text(report)
        self.assertIn("result: reproducible", text)
        self.assertNotIn("likely causes", text)

        report["reproducible"] = False
        report["builds"][1]["sha256"] = "b" * 64
        report["likely_causes"] = repro.explain_mismatch()
        text = repro.render_text(report)
        self.assertIn("result: MISMATCH", text)
        self.assertIn("likely causes", text)


if __name__ == "__main__":
    unittest.main()
