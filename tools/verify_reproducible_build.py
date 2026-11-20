#!/usr/bin/env python3
"""Rebuild a release binary twice and compare its SHA-256 digest.

This is an evidence tool, not a guarantee. It records the toolchain and the
environment inputs, builds the same source twice in separate target directories
with a fixed environment, and reports whether the resulting binaries are
byte-for-byte identical. A mismatch is reported with likely causes; the script
never claims reproducibility that it did not observe.

Read-only with respect to the repository. No network access is required once the
dependencies are available locally.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Inputs that are fixed for every build unless the caller overrides them.
FIXED_ENV = {
    "SOURCE_DATE_EPOCH": "0",
    "CARGO_INCREMENTAL": "0",
}

MISMATCH_HINTS = [
    "The Rust toolchain differs between builds (compare rustc -Vv and cargo -V).",
    "Incremental compilation or a reused target directory produced stale objects.",
    "Build paths differ; absolute paths can leak into debug info or panic messages.",
    "Parallel codegen or a non-deterministic proc-macro/linker changed the output.",
    "Environment values such as RUSTFLAGS, CARGO_PROFILE_*, or locale differ.",
    "The linker or system libraries differ between the two target directories.",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_host(toolchain: str) -> str | None:
    for line in toolchain.splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    return None


def binary_name(package: str, target_triple: str | None) -> str:
    suffix = ".exe" if target_triple and "windows" in target_triple else ""
    return f"{package}{suffix}"


def binary_path(target_dir: Path, package: str, target_triple: str | None) -> Path:
    return target_dir / "release" / binary_name(package, target_triple)


def explain_mismatch() -> list[str]:
    return list(MISMATCH_HINTS)


def _run(command: list[str], env: dict[str, str], cwd: Path) -> str:
    result = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stdout}"
        )
    return result.stdout


def read_toolchain(cwd: Path) -> dict[str, str | None]:
    env = os.environ.copy()
    rustc = _run(["rustc", "-Vv"], env, cwd).strip()
    cargo = _run(["cargo", "-V"], env, cwd).strip()
    return {
        "rustc": rustc,
        "cargo": cargo,
        "host": parse_host(rustc),
    }


def build_once(
    manifest: Path,
    package: str,
    target_dir: Path,
    env_overrides: dict[str, str],
) -> Path:
    env = os.environ.copy()
    env.update(FIXED_ENV)
    env.update(env_overrides)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    _run(
        [
            "cargo",
            "build",
            "--release",
            "--locked",
            "--manifest-path",
            str(manifest),
            "--package",
            package,
        ],
        env,
        manifest.parent,
    )
    return target_dir


def verify(
    manifest: Path,
    package: str,
    env_overrides: dict[str, str] | None = None,
    work_dir: Path | None = None,
) -> dict:
    env_overrides = env_overrides or {}
    toolchain = read_toolchain(manifest.parent)
    created = work_dir is None
    base = work_dir or Path(tempfile.mkdtemp(prefix="soroban-repro-"))
    try:
        digests = []
        sizes = []
        for index in (1, 2):
            target = base / f"target-{index}"
            build_once(manifest, package, target, env_overrides)
            artifact = binary_path(target, package, toolchain["host"])
            if not artifact.exists():
                raise RuntimeError(f"expected binary not found: {artifact}")
            digests.append(sha256_file(artifact))
            sizes.append(artifact.stat().st_size)
        match = digests[0] == digests[1]
        report = {
            "package": package,
            "manifest": str(manifest),
            "toolchain": toolchain,
            "environment": {**FIXED_ENV, **env_overrides},
            "builds": [
                {"attempt": 1, "sha256": digests[0], "bytes": sizes[0]},
                {"attempt": 2, "sha256": digests[1], "bytes": sizes[1]},
            ],
            "reproducible": match,
        }
        if not match:
            report["likely_causes"] = explain_mismatch()
        return report
    finally:
        if created:
            shutil.rmtree(base, ignore_errors=True)


def render_text(report: dict) -> str:
    lines = [
        f"package: {report['package']}",
        f"manifest: {report['manifest']}",
        f"rustc: {report['toolchain']['rustc'].splitlines()[0]}",
        f"cargo: {report['toolchain']['cargo']}",
        f"host: {report['toolchain']['host']}",
        "environment:",
    ]
    for key, value in sorted(report["environment"].items()):
        lines.append(f"  {key}={value}")
    lines.append("builds:")
    for build in report["builds"]:
        lines.append(
            f"  attempt {build['attempt']}: sha256={build['sha256']} bytes={build['bytes']}"
        )
    if report["reproducible"]:
        lines.append("result: reproducible (identical SHA-256)")
    else:
        lines.append("result: MISMATCH (different SHA-256)")
        lines.append("likely causes:")
        for hint in report.get("likely_causes", []):
            lines.append(f"  - {hint}")
    return "\n".join(lines) + "\n"


def parse_env(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values:
        if "=" not in item:
            raise argparse.ArgumentTypeError(
                f"environment override must be KEY=VALUE, got {item!r}"
            )
        key, value = item.split("=", 1)
        if not key:
            raise argparse.ArgumentTypeError("environment override has an empty key")
        parsed[key] = value
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Rebuild a release binary twice and compare its SHA-256 digest."
    )
    parser.add_argument(
        "--manifest-path",
        type=Path,
        default=Path("Cargo.toml"),
        help="Path to the crate's Cargo.toml (default: Cargo.toml).",
    )
    parser.add_argument(
        "--package",
        default="soroban-scan-cli",
        help="Cargo package to build (default: soroban-scan-cli).",
    )
    parser.add_argument(
        "--env",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Extra environment input for both builds (repeatable).",
    )
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="Keep build directories under this path instead of a temp directory.",
    )
    parser.add_argument("--json", action="store_true", help="Emit a JSON report.")
    args = parser.parse_args(argv)

    try:
        env_overrides = parse_env(args.env)
        report = verify(
            args.manifest_path.resolve(),
            args.package,
            env_overrides,
            args.work_dir,
        )
    except (RuntimeError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_text(report))
    return 0 if report["reproducible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
