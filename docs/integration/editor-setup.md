# Editor setup: VS Code and Neovim

This guide shows the minimal configuration needed to connect `soroban-scan` to
VS Code and Neovim over the Language Server Protocol (LSP), and lists what the
server supports and what it does not.

> **Status: the server is not shipped yet.** The `soroban-scan lsp` subcommand
> described in the [editor integration spec](editor-integration.md) (issue #168)
> is a design record, not an implementation. The configurations below target
> that planned interface (stdio transport, no extra arguments) and have **not**
> been verified against a running server. Verify them manually once the
> subcommand lands, and update this page if the final command line differs.
> Until then, use the CLI in your terminal or in CI: see the
> [CLI reference](../cli.md) and [CI recipes](../ci-recipes.md).

## Prerequisites

- `soroban-scan` installed and on your `PATH`. It is not yet published to
  crates.io, so install it from source:

  ```bash
  cargo install --path crates/soroban-scan-cli
  ```

- An editor with LSP support: VS Code, or Neovim 0.8+ with
  [`nvim-lspconfig`](https://github.com/neovim/nvim-lspconfig).

The server communicates over stdio only. It opens no network port, makes no
network requests, and never compiles, executes, or modifies the code it scans.
No credentials or API keys are needed or should be placed in editor settings.

## VS Code

VS Code has no built-in way to launch an arbitrary language server, and a
dedicated Soroban client extension is a separate follow-up item in the spec. In
the meantime, a generic LSP client extension can launch the server. The exact
setting names depend on the extension you choose; the part that matters is the
command and the file selector:

| Setting | Value |
| ------- | ----- |
| Command | `soroban-scan` |
| Arguments | `lsp` |
| Transport | stdio |
| Document selector | language `rust`, scheme `file` |
| Workspace root | folder containing `Cargo.toml` or `soroban-scan.toml` |

Open a Soroban contract crate as the workspace folder so the server can find the
project and its configuration.

## Neovim (nvim-lspconfig)

`soroban-scan` is not a built-in `nvim-lspconfig` server, so register it as a
custom config. This works in Lua with `init.lua`:

```lua
local lspconfig = require("lspconfig")
local configs = require("lspconfig.configs")

if not configs.soroban_scan then
  configs.soroban_scan = {
    default_config = {
      cmd = { "soroban-scan", "lsp" },
      filetypes = { "rust" },
      root_dir = lspconfig.util.root_pattern("soroban-scan.toml", "Cargo.toml"),
      single_file_support = false,
    },
  }
end

lspconfig.soroban_scan.setup({})
```

Run `:LspInfo` in a Rust buffer to confirm that `soroban_scan` is attached.
Diagnostics show through Neovim's normal diagnostic UI (`vim.diagnostic`), with
`soroban-scan` as the diagnostic source.

## Supported LSP capabilities

The first milestone is a deliberately small diagnostics provider (option C in the
[spec](editor-integration.md)):

| Capability | Supported |
| ---------- | --------- |
| `initialize`, `initialized`, `shutdown`, `exit` | Yes |
| `textDocument/didOpen`, `didChange` (debounced), `didSave`, `didClose` | Yes |
| `textDocument/publishDiagnostics` | Yes |
| `workspace/didChangeConfiguration` | Planned, not in v1 |
| `textDocument/codeAction` (suppression quick fixes only) | Yes |
| Other code actions and autofix | No |
| Hover, completion, formatting, rename, refactoring | No |

Each diagnostic carries the rule id, severity, confidence, message, and an exact
source range, with `soroban-scan` as the source. Findings use the same
configuration, excludes, and suppressions as the CLI, so editor and CLI results
do not drift. Suppressed findings are not published.

## Known limitations

- **Not implemented yet.** See the status note at the top of this page.
- **Diagnostics plus suppression quick fixes.** The only code action inserts a
  documented inline suppression directive for a scanner diagnostic. There are
  no hover documentation or baseline-suppression actions in v1.
- **Project context.** A single-file scan can disagree with a full project scan
  for rules that need project context. The server prefers a debounced project
  scan and falls back to a single-file scan for large or unloadable projects;
  the mode is meant to be visible in the diagnostic source.
- **Bounded scans.** File count, file size, and scan time are capped. On timeout
  the server keeps the previous results and publishes an informational
  diagnostic instead of reporting a clean scan.
- **Static analysis only.** Findings are hypotheses with a stated confidence,
  not proof. See [Analysis Methodology](../analysis-methodology.md).
- **No AI assistance and no telemetry** in the editor path.
- **CLI remains the source of truth.** Editor diagnostics do not replace CI
  gating or the `--fail-on` policy.
- **Other editors** (Helix, Emacs, Zed, JetBrains) should work through their
  generic LSP clients with the same command, but recipes for them are not
  provided or tested here.
