# Supporting Tooling

This directory contains **Python supporting tooling**. Nothing here is on the
critical scanning path — the scanner itself is pure Rust. These tools exist for
out-of-band automation such as:

- Generating and validating the contributor backlog.
- Maintaining the security fixture corpus.
- Validating the pinned Soroban SDK compatibility matrix.
- Validating the published OpenAPI 3.1.0 contract (`check_openapi.py`).
- Release and changelog automation.

## Requirements

- Python 3.10+

## Conventions

- Standard library only unless a dependency is clearly justified.
- Each tool supports `--help`.
- Tools must be safe to run: no network access, no destructive filesystem
  operations outside the repository, and no handling of secrets.
