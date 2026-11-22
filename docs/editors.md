# Editor setup (VS Code and Neovim)

Connect the Soroban Security Scanner language server to VS Code or Neovim.
This is opt-in: nothing runs until you configure it. The server uses stdio,
needs no network access, and requires no secrets. Do not put credentials in
your editor config.

## Prerequisites

```bash
cargo install --path .
<BIN> <LSP_ARG>   # starts the server on stdio; press Ctrl+C to exit
```

## Supported LSP capabilities

| Capability | Supported |
|---|---|
| Diagnostics (publishDiagnostics) | Yes |
| Text document sync | Yes |
| Document symbols (outline) | Yes |
| Hover (rule ids) | Yes |
| Code actions | No |
| Completion | No |

The outline lists contracts (`#[contract]` / `#[contractimpl]`), functions,
`#[contracttype]` structs and enums, and `#[contractevent]` declarations.
Function ranges cover the signature span exposed by the parser; the body end
line is not tracked, so an outline entry may end on the `fn` signature line.

Hover a `SS-###` rule id in a comment or source line to see its title,
severity, confidence, category, description, and remediation. The text comes
from the in-process rule registry: no network request, file read, or external
documentation lookup is performed. An unregistered id shows a short fallback
instead of an error.

## Workspace configuration

The server reads `soroban-scan.toml` from the workspace root reported by the
LSP `initialize` request (`workspaceFolders` or `rootUri`). It uses the same
parser and validation as the CLI, so thresholds, rule toggles, overrides,
suppressions, and other scan settings apply to editor diagnostics. If no file
exists, the default configuration is used.

Configuration is reloaded when the client sends
`workspace/didChangeConfiguration` or `workspace/didChangeWatchedFiles`, and
open documents are re-diagnosed without restarting the server. An invalid file
keeps the last valid configuration (or the defaults) and publishes an error
diagnostic (`LSP-CONFIG-001`) with source `soroban-scan` on the configuration
file.

## VS Code

1. Install the **Generic LSP Client** extension (`llllvvuu.glspc`).
2. Open user settings JSON (`Ctrl+Shift+P`, then "Preferences: Open User Settings (JSON)") and add:

```json
{
  "glspc.server.command": "<BIN>",
  "glspc.server.commandArguments": ["<LSP_ARG>"],
  "glspc.server.languageId": ["rust"]
}
```

3. Run "Developer: Reload Window", then open a Soroban `.rs` file.
   Diagnostics appear in the Problems panel.

## Neovim

Neovim 0.11 or newer, in `init.lua`:

```lua
vim.lsp.config['soroban-scanner'] = {
  cmd = { '<BIN>', '<LSP_ARG>' },
  filetypes = { 'rust' },
  root_markers = { 'Cargo.toml', '.git' },
}
vim.lsp.enable('soroban-scanner')
```

Neovim 0.8 to 0.10:

```lua
vim.api.nvim_create_autocmd('FileType', {
  pattern = 'rust',
  callback = function(args)
    vim.lsp.start({
      name = 'soroban-scanner',
      cmd = { '<BIN>', '<LSP_ARG>' },
      root_dir = vim.fs.root(args.buf, { 'Cargo.toml', '.git' }),
    })
  end,
})
```

Verify with `:checkhealth vim.lsp`. The client should be attached to the buffer.

## Known limitations

- Only Rust (`.rs`) files are analyzed.
- Completion and code actions are not implemented.
- Hover only recognizes `SS-###` tokens; hovering a symbol name or a diagnostic
  message body returns nothing.
- The server uses full-document sync. Diagnostics refresh on open, change, and
  save; a change replaces the whole document buffer.
- The language server uses no network access. It reads only the workspace
  `soroban-scan.toml` and runs the default rule set when none is configured.
- Function and event symbol ranges use the parser's signature span, so the end
  line may be the declaration line rather than the closing brace.

## Troubleshooting

- `command not found`: add `~/.cargo/bin` to `PATH` or use the absolute binary path.
- No diagnostics: check the server started (VS Code: Output panel; Neovim: `:LspLog`).