# Editor setup (VS Code and Neovim)

Connect the Soroban Security Scanner language server to VS Code or Neovim.
This is opt-in: nothing runs until you configure it. The server uses stdio,
needs no network access, and requires no secrets. Do not put credentials in
your editor config.

## Prerequisites

```bash
cargo install --path .
soroban-scan-lsp  # standalone stdio server; press Ctrl+C to exit
# Alternatively, use the existing CLI subcommand: soroban-scan lsp
```

## Supported LSP capabilities

| Capability | Supported |
|---|---|
| Diagnostics (publishDiagnostics) | Yes |
| Text document sync | Yes |
| Document symbols (outline) | Yes |
| Hover (rule ids) | Yes |
| Code actions (suppression quick fixes) | Yes |
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

A `SS-###` diagnostic also offers a **quick fix** that inserts the documented
inline suppression directive with the exact rule id and a required
`TODO: explain why this finding is accepted` reason placeholder. The edit is
returned to the editor as a normal `WorkspaceEdit`; the server never writes the
file and never suppresses a finding by itself. Replace the placeholder with a
real reason before committing. See [inline suppressions](suppressions.md#editor-quick-fix).

## Diagnostic ranges and severities

The scanner reports 1-based line and byte-column spans. The language server
converts them to LSP positions before publishing:

- LSP lines and characters are zero-based.
- Columns are counted in UTF-16 code units, not bytes. A multi-byte character
  takes one or two UTF-16 units; a byte offset inside a character is clamped to
  the character start.
- CRLF line endings are stripped before counting, so `\r` never shifts a
  position.
- Positions past the end of the document or line are clamped instead of
  producing an out-of-range diagnostic.

Severity combines the finding severity with its confidence:

| Finding severity | Confidence | LSP severity |
|---|---|---|
| critical, high | medium, high | Error |
| critical, high | low | Warning |
| medium | any | Warning |
| low | any | Information |
| info | any | Hint |

A low-confidence finding is capped at Warning so a heuristic result is not
presented with more certainty than the detector has. The diagnostic `data`
field also carries the finding fingerprint and lowercase confidence.

## Performance limits

Live analysis is bounded so a large buffer or a burst of edits cannot block the
server:

| Limit | Value | Behavior when exceeded |
|---|---|---|
| Retained source per document | 1 MiB | Oversized content is discarded, analysis and outline/hover are skipped, and a `LSP-DOCUMENT-LIMIT` warning is published. |
| Analysis time | 2 seconds | The worker result is discarded and an `LSP-ANALYSIS-TIMEOUT` warning is published. |
| Diagnostics per document | 200 | The remaining diagnostics are dropped and an `LSP-DIAGNOSTICS-TRUNCATED` warning is published with the omitted count. |
| Change debounce | 150 ms | Analysis starts after the typing pause. |

Analysis runs on a worker thread. A newer edit increments the document
generation, and a result from an older generation is discarded instead of
overwriting newer diagnostics. Changes to a document that is already being
analyzed wait for that analysis (or its timeout) before starting again, so a
burst of keystrokes cannot create an unbounded number of scan threads. These
limits are fixed and need no configuration; the server remains offline and
reads no secrets.

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
  "glspc.server.command": "soroban-scan-lsp",
  "glspc.server.commandArguments": [],
  "glspc.server.languageId": ["rust"]
}
```

If you prefer the main CLI binary, set `glspc.server.command` to
`soroban-scan` and `glspc.server.commandArguments` to `["lsp"]`.

3. Run "Developer: Reload Window", then open a Soroban `.rs` file.
   Diagnostics appear in the Problems panel.

## Neovim

Neovim 0.11 or newer, in `init.lua`:

```lua
vim.lsp.config['soroban-scanner'] = {
  cmd = { 'soroban-scan-lsp' },
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
      cmd = { 'soroban-scan-lsp' },
      root_dir = vim.fs.root(args.buf, { 'Cargo.toml', '.git' }),
    })
  end,
})
```

Verify with `:checkhealth vim.lsp`. The client should be attached to the buffer.
To use the main CLI instead, set `cmd = { 'soroban-scan', 'lsp' }`.

## Known limitations

- Only Rust (`.rs`) files are analyzed.
- Completion is not implemented. Code actions are limited to suppression quick
  fixes for scanner diagnostics (no bulk fixes or rule autofixes).
- Hover only recognizes `SS-###` tokens; hovering a symbol name or a diagnostic
  message body returns nothing.
- The server uses full-document sync. Diagnostics refresh on open, change, and
  save; a change replaces the whole document buffer.
- Source buffers over 1 MiB are not retained, so they have no diagnostics,
  outline, or hover until the document is reduced below the limit.
- The language server uses no network access. It reads only the workspace
  `soroban-scan.toml` and runs the default rule set when none is configured.
- Function and event symbol ranges use the parser's signature span, so the end
  line may be the declaration line rather than the closing brace.

## Troubleshooting

- `command not found`: add `~/.cargo/bin` to `PATH` or use the absolute binary path.
- No diagnostics: check the server started (VS Code: Output panel; Neovim: `:LspLog`).