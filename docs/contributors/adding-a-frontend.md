# Adding a language frontend

A frontend teaches the scanner how to discover, read, and represent one source
language. Rules stay language-neutral where possible: they consume the parsed
items and facts a frontend produces, so a new frontend does not require a new
rule pipeline.

> **Experimental status.** Only the Rust frontend is supported. A new frontend
> is experimental until a maintainer reviews it against this guide and the
> conformance suite. It is not covered by the stability promises in
> [`../api-stability.md`](../api-stability.md) and must not be advertised as a
> supported language in the README, CLI help, or detection output before that
> review.

## What the scanner is

`soroban-scan` is a deterministic CLI scanner. It does not run a service, build
the scanned project, execute contracts, fetch dependencies, or write to the
scan root. A frontend inherits those limits: it may read files below the scan
root and parse them, and nothing else.

## The `Frontend` trait

The trait lives in
[`crates/soroban-scan-core/src/frontend.rs`](../../crates/soroban-scan-core/src/frontend.rs):

```rust
pub trait Frontend {
    fn name(&self) -> &'static str;
    fn discover(&self, root: &Path, opts: &DiscoveryOptions) -> Result<Discovered, ScanError>;
    fn load(&self, root: &Path, opts: &DiscoveryOptions) -> Result<LoadedProject, ScanError>;
    fn load_files(
        &self,
        root: &Path,
        files: &[PathBuf],
        opts: &DiscoveryOptions,
    ) -> Result<LoadedProject, ScanError>;
}
```

| Method | Contract |
| ------ | -------- |
| `name` | Stable lowercase language name used in reports (`rust` today). |
| `discover` | Returns manifests and source files found below `root`, sorted and inside `root`. It must not follow symlinks unless options allow it. |
| `load` | Calls discovery, then parses each source into items, functions, spans, imports, and contract evidence. |
| `load_files` | Same as `load`, but for an explicit file list (single-file scans). |

`LoadedProject` carries project metadata, parsed sources, and diagnostics.
Malformed source files become `PARSE-001` warnings, not fatal errors. Only a
missing or unreadable root manifest should fail the load.

The engine runs rules after loading. A frontend does not decide which rules run;
it supplies syntax and facts. Detection metadata must report the frontend's own
`name`, not `rust`, and rule selection stays conservative when evidence is
incomplete.

## Minimal skeleton

The following skeleton compiles as
[`crates/soroban-scan-core/tests/frontend_skeleton.rs`](../../crates/soroban-scan-core/tests/frontend_skeleton.rs).
It delegates to the Rust loader so it stays short; a real frontend replaces the
body of each method with its own parser and model construction.

```rust
use std::path::{Path, PathBuf};

use soroban_scan_core::discovery::{self, Discovered, DiscoveryOptions};
use soroban_scan_core::error::ScanError;
use soroban_scan_core::frontend::{Frontend, LoadedProject};
use soroban_scan_core::project;

struct ExampleFrontend;

impl Frontend for ExampleFrontend {
    fn name(&self) -> &'static str {
        "example"
    }

    fn discover(&self, root: &Path, opts: &DiscoveryOptions) -> Result<Discovered, ScanError> {
        discovery::discover(root, opts)
    }

    fn load(&self, root: &Path, opts: &DiscoveryOptions) -> Result<LoadedProject, ScanError> {
        project::load(root, opts)
    }

    fn load_files(
        &self,
        root: &Path,
        files: &[PathBuf],
        opts: &DiscoveryOptions,
    ) -> Result<LoadedProject, ScanError> {
        project::load_files_with_options(root, files, opts)
    }
}
```

Run it with the rest of the suite:

```bash
cargo test -p soroban-scan-core --test frontend_skeleton
```

The skeleton is a compile-time contract, not a usable frontend. Before it can
be selected by the CLI, the frontend must be wired into the engine or CLI
alongside the default Rust frontend. That integration is part of the review, not
something the trait does automatically.

## Conformance suite

Every frontend must pass the reusable harness in
[`crates/soroban-scan-core/tests/conformance/mod.rs`](../../crates/soroban-scan-core/tests/conformance/mod.rs).
The Rust frontend runs it from
[`frontend_conformance.rs`](../../crates/soroban-scan-core/tests/frontend_conformance.rs).
An in-repo frontend includes the same module and supplies:

- a valid project fixture that loads without parse errors;
- a second fixture with at least one unparseable source file;
- the exact expected `name` value.

```rust
mod conformance;

use soroban_scan_core::frontend::MyFrontend;

#[test]
fn my_frontend_conforms() {
    let failures = conformance::check(&conformance::Case {
        frontend: &MyFrontend,
        expected_name: "mylang",
        root: &fixture("projects/my-valid-project"),
        broken_root: &fixture("projects/parse-error"),
    });
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
```

The harness checks the stable name, deterministic discovery, paths inside the
root, a fatal error for a missing root, source/load agreement, non-empty items,
non-zero and ordered spans, deterministic repeated loads, `load_files`
consistency, and a `PARSE-001` warning (with the parse error retained) for the
broken fixture. It reports every failure in one run instead of stopping at the
first.

The harness is a test module, not a published crate API. Copy it into a new
crate's tests if the frontend lives outside this workspace, and keep the copy in
sync with the upstream module.

## Fixtures

Fixtures are small and synthetic. Never copy real contracts, secrets, private
keys, or addresses into them.

| Fixture | Purpose |
| ------- | ------- |
| `fixtures/projects/<name>/` | A complete mini-project: manifest plus source. |
| `fixtures/projects/parse-error/` | A source file that must produce `PARSE-001` without aborting the load. |
| `fixtures/corpus/<RULE-ID>/` | Rule regression samples, not frontend fixtures. |

The fixture must exercise the constructs the frontend claims to support:
entry points, items, nested modules, imports, and at least one construct that
must produce a diagnostic. Keep the expected behavior next to the fixture when
it is not obvious.

## Limits and review checklist

A frontend must not:

- execute, compile, build, sign, deploy, or mutate scanned code;
- read outside the scan root, including `~`, environment files, or the network;
- fabricate items, spans, contract evidence, or detection confidence;
- hide parse failures: record a diagnostic and continue with the other files;
- report a language or project type it cannot prove.

A frontend is ready for review only when:

- [ ] The skeleton above compiles and the conformance suite passes.
- [ ] A valid fixture and a broken fixture are committed.
- [ ] Detection metadata reports the new language only when evidence exists.
- [ ] Paths are relative, sorted, and confined to the scan root.
- [ ] The CLI/engine integration is included, or the guide and PR state that the
      frontend is not yet selectable.
- [ ] `docs/architecture/workspace-layout.md` and the public API notes are
      updated if a new module is added.
- [ ] The language is marked **experimental** in the PR and in the docs until a
      maintainer accepts it.

The full local gate applies:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
python tools/check_docs.py
```
