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
| Hover | No |
| Code actions | No |
| Completion | No |

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
- Hover, completion, and code actions are not implemented.
- Diagnostics may refresh only on open or save.

## Troubleshooting

- `command not found`: add `~/.cargo/bin` to `PATH` or use the absolute binary path.
- No diagnostics: check the server started (VS Code: Output panel; Neovim: `:LspLog`).