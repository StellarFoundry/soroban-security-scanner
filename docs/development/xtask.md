# Repository Automation (`xtask`)

Repository automation lives in the `xtask` workspace crate. It is a typed,
portable entry point for the maintenance tasks that used to be Python-only.
Every command is **offline** and **non-destructive**.

```bash
cargo xtask --help
```

```
Usage: xtask <COMMAND>

Commands:
  docs      Check relative links in every Markdown file
  fixtures  Scaffold a project fixture under fixtures/projects/
  backlog   Render the contributor backlog from tools/backlog/*.json
  corpus    Report per-rule corpus fixture counts, docs presence, and validation status [aliases: coverage]
```

The alias is defined in `.cargo/config.toml`:

```toml
[alias]
xtask = "run --package xtask --"
```

## `cargo xtask docs`

Checks every `*.md` file for relative links that point at a missing file. It is
a Rust reimplementation of `tools/check_docs.py` and produces the same summary:

```bash
cargo xtask docs
# OK: checked 79 Markdown files, no broken relative links.
```

External URLs, `mailto:` links, anchors, and `<...>` targets are not fetched or
checked. `.git`, `target`, `node_modules`, and `vendor` are skipped.

Use `--root <dir>` to check another checkout.

## `cargo xtask fixtures <name>`

Scaffolds a project fixture under `fixtures/projects/<name>`:

```bash
cargo xtask fixtures nested-call
cargo xtask fixtures nested-call --force   # overwrite scaffold files only
```

The generated fixture is a minimal, parseable Rust crate (`Cargo.toml` and
`src/lib.rs`) intended as a starting point for a regression corpus. Fixture
names are restricted to letters, digits, `-`, and `_`; path traversal is
rejected. Existing fixtures are never overwritten without `--force`, and
`--force` only replaces the two scaffold files — unrelated files are left
intact.

## `cargo xtask backlog`

Renders the contributor backlog from `tools/backlog/*.json` into Markdown issue
bodies, mirroring the body format of `tools/create_backlog.py`:

```bash
cargo xtask backlog                  # writes target/backlog/NNN-<slug>.md
cargo xtask backlog --check          # validate JSON and duplicate titles only
cargo xtask backlog --output /tmp/backlog
```

`--check` parses every file, verifies required fields and bullet types, and
rejects duplicate titles. It does not write anything and does not contact
GitHub. Creating labels and issues still requires `gh`, so that step remains in
`tools/create_backlog.py` until xtask reaches parity.

## `cargo xtask corpus`

Summarizes per-rule corpus coverage across all discovered rules (`fixtures/corpus/`,
`docs/rules/detectors/`, and `crates/soroban-scan-core/src/rules/`):

```bash
cargo xtask corpus                      # aligned terminal table
cargo xtask corpus --format markdown    # GitHub-flavored Markdown table
cargo xtask corpus --check              # fail if any rule has a corpus or docs gap
```

For each rule, the report lists:

- Rule ID (`SS-NNN`).
- Number of positive (`positive*.rs` / `positive*.toml`), negative (`negative*.rs` / `negative*.toml`), and must-trigger (`must_trigger*` / `must-trigger*`) fixtures under `fixtures/corpus/<ID>/`.
- Presence of `docs/rules/detectors/<ID>.md`.
- Validation status (`ok` or gap summary when a rule is missing a positive fixture, has fewer than 3 negative fixtures, or lacks documentation).

## Relationship to the Python tools

The Python helpers under `tools/` remain supported and unchanged:

| Task | Python | xtask |
| ---- | ------ | ----- |
| Markdown link check | `python tools/check_docs.py` | `cargo xtask docs` |
| Fixture scaffolding | — | `cargo xtask fixtures <name>` |
| Render backlog bodies | `python tools/create_backlog.py` (creates issues) | `cargo xtask backlog` (offline render) |
| Corpus coverage report | — | `cargo xtask corpus` |

xtask only replaces read-only and local-generation work. Anything that needs
credentials or the network stays opt-in in the Python tooling.
