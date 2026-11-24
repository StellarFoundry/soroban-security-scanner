"""Structural checks for the opt-in container image definition.

This is not a Docker build. CI builds the image in the ``docker`` job; these
tests keep the pinned bases, non-root runtime, documented entry point, and
minimal build context from drifting.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCKERFILE = ROOT / "Dockerfile"
IGNORE = ROOT / ".dockerignore"
DOC = ROOT / "docs" / "docker.md"
CI = ROOT / ".github" / "workflows" / "ci.yml"


def dockerfile_text() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


class DockerfileTests(unittest.TestCase):
    def test_multi_stage_build_uses_pinned_bases(self):
        text = dockerfile_text()
        stages = re.findall(r"^FROM\s+(.+)$", text, re.MULTILINE)
        self.assertEqual(len(stages), 2, "expected a builder stage and a runtime stage")
        self.assertIn("AS builder", stages[0])
        self.assertNotIn("AS ", stages[1])
        for stage in stages:
            self.assertRegex(
                stage,
                r":\d+\.\d+\.\d+[^\s]*@sha256:[0-9a-f]{64}",
                f"base image must pin a patch tag and a digest: {stage}",
            )
            self.assertNotIn("latest", stage)

    def test_runtime_stage_is_non_root_and_minimal(self):
        text = dockerfile_text()
        self.assertIn("USER 65532:65532", text)
        self.assertNotIn("USER root", text)
        self.assertNotIn("COPY . .", text)
        self.assertNotIn("ADD .", text)
        self.assertRegex(
            text,
            r"COPY --from=builder \S+/soroban-scan /usr/local/bin/soroban-scan",
        )
        runtime = text.rsplit("FROM ", 1)[1]
        self.assertNotIn("apk add", runtime)
        self.assertNotIn("apt-get", runtime)
        self.assertNotIn("COPY .", runtime)

    def test_entry_point_and_health_check_are_documented_in_the_image(self):
        text = dockerfile_text()
        self.assertIn('ENTRYPOINT ["soroban-scan"]', text)
        self.assertIn('CMD ["scan", ".", "--fail-on", "high"]', text)
        self.assertRegex(
            text,
            r'HEALTHCHECK[\s\S]*?CMD \["soroban-scan", "version"\]',
        )

    def test_no_secrets_are_baked_in(self):
        text = dockerfile_text()
        self.assertNotRegex(
            text,
            r"(?im)^\s*ENV\s+\S*(TOKEN|SECRET|PASSWORD|PRIVATE_KEY|CREDENTIAL)",
        )
        ignore = {line.strip() for line in IGNORE.read_text(encoding="utf-8").splitlines()}
        for pattern in (".env", ".env.*", "*.pem", "*.key", ".netrc"):
            self.assertIn(pattern, ignore)

    def test_dockerignore_excludes_the_repository_and_keeps_the_workspace(self):
        ignore = {
            line.strip()
            for line in IGNORE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
        for pattern in (
            ".git/",
            "target/",
            "fixtures/",
            "examples/",
            "docs/",
            "deploy/",
            "tests/",
            "tools/",
            "!README.md",
        ):
            self.assertIn(pattern, ignore)
        for required in ("Cargo.toml", "Cargo.lock", "crates/", "xtask/", ".cargo/"):
            self.assertNotIn(required, ignore)

    def test_docs_and_ci_cover_build_run_and_non_root(self):
        doc = DOC.read_text(encoding="utf-8")
        for fragment in (
            "docker build",
            "docker run",
            "ENTRYPOINT",
            "HEALTHCHECK",
            "65532",
            "non-root",
            "fixtures/corpus/SS-001",
        ):
            self.assertIn(fragment, doc)

        ci = CI.read_text(encoding="utf-8")
        for fragment in ("docker build", "docker run", "fixtures/corpus/SS-001"):
            self.assertIn(fragment, ci)


if __name__ == "__main__":
    unittest.main()
