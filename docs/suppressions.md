# Inline suppressions

An inline suppression directive removes a single finding (or a single item's
findings) from the failure gate **without weakening a rule project-wide**. Every
suppression stays visible: suppressed findings and their reasons are reported in
terminal, JSON, SARIF and Markdown output, and they are never dropped silently.

## Pattern

```text
// soroban-scan: ignore SS-XXX[, SS-YYY ...] [-- reason]
```

- The marker `soroban-scan:` is matched case-insensitively.
- The keyword is `ignore`.
- Targets are one or more rule ids (`SS-` plus three digits) separated by commas
  or whitespace, or the literal `all` for every rule.
- An optional reason follows a `--` separator. Reasons are reported verbatim and
  make audits possible; they are not required but are strongly recommended.

The pattern is stable: it only changes in a release that documents the change in
[CHANGELOG.md](../CHANGELOG.md).

### Examples

```rust
// soroban-scan: ignore SS-001 -- the vault is intentionally permissionless
pub fn deposit(env: Env, from: Address, amount: i128) {
    // ...
}

// soroban-scan: ignore SS-006, SS-008 -- TTL policy handled centrally
mod generated;

/* soroban-scan: ignore all -- vendored, reviewed separately */
```

A directive that trails a line of code applies to that line:

```rust
let total = a + b; // soroban-scan: ignore SS-008 -- values are bounded above
```

## What a directive applies to

A directive is anchored to the code line it trails or to the first code line
below it. At most three lines of blanks and other comments may separate the
directive from the code it applies to.

- If the anchored line is the first line of an item (a function, `impl`, `mod`,
  and so on), or the attribute line directly above it, the directive covers the
  **whole item**.
- Otherwise the directive covers that **single line**, which is how you suppress
  one finding inside a function body.

```rust
// soroban-scan: ignore SS-001 -- covers the whole impl block below
#[contractimpl]
impl Vault {
    pub fn set_admin(env: Env, admin: Address) {
        // soroban-scan: ignore SS-006 -- covers only the next line
        env.storage().persistent().set(&symbol_short!("ADMIN"), &admin);
    }
}
```

## What a directive never matches

Detection is lexical and never executes the analyzed code. The following are
**not** directives:

- text inside string literals, byte strings, raw strings, or character literals;
- text inside block comments that are not closed on the same line, including a
  directive that is still inside an outer comment because block comments nest,
  as in `/* /* */ soroban-scan: ignore SS-001 */`;
- comments that are not adjacent to code (more than three lines away);
- malformed directives, for example `// soroban-scan: ignore`,
  `// soroban-scan: ignore SS-1`, or an unknown keyword such as
  `// soroban-scan: allow SS-001`.

Character literals are recognized as literals, so a quote or an apostrophe that
they contain never turns the following lines into string text: a directive after
`let quote = '"';` is still found.

## Editor quick fix

The language server offers a `quickfix` code action for each `SS-###` scanner
diagnostic. Accepting it inserts a standalone directive immediately above the
reported line, reusing that line's indentation and the document's line endings:

```rust
// soroban-scan: ignore SS-001 -- TODO: explain why this finding is accepted
env.storage().persistent().set(&1u32, &value);
```

The rule id comes from the diagnostic and the reason is a **required
placeholder**, not a real justification: a suppression is never created
silently, and the inserted comment is visible in the editor and in the diff.
Replace the placeholder with the actual reason before committing. The action is
skipped when the document already contains a directive for that rule (or for
`all`), and only scanner diagnostics are eligible: configuration and truncation
diagnostics cannot be suppressed this way. The server returns a `WorkspaceEdit`
and never writes files itself.

## Reporting

Suppressions never hide findings. The scanner:

- removes suppressed findings from the gate (`--fail-on` never triggers on them);
- keeps them in the report:
  - **terminal** — a `Suppressions:` count in the header and a `N suppressed
    finding(s)` section listing each finding, the directive that suppressed it,
    and the reason;
  - **JSON** — the `suppressed` array (each entry carries the finding plus a
    `suppression` object with `file`, `line`, `rules` and `reason`), the
    `suppressions` array of every detected directive (with `applied` telling you
    whether it suppressed anything), and the `stats.findings_suppressed` /
    `stats.suppressions_detected` counters;
  - **SARIF** — suppressed findings stay in `results` and are marked as in-source
    suppressions:
    `"suppressions": [{ "kind": "inSource", "status": "accepted", "justification": "..." }]`.
    Rule descriptors also carry `help.text` / `help.markdown` and
    `properties.remediation` / `properties.references`;
  - **Markdown** — a `## Suppressed findings` section.

Unused directives are reported too (`applied: false`), which makes stale or
mistyped suppressions visible in review.

## Related

- [Baselines](baselines.md) — suppress known findings across a whole project.
- [Waivers](cli.md#waivers-with-expiry) — time-limited, owned suppressions with
  an audit trail.
- [Configuration](configuration.md) — disable or re-scope rules project-wide.
- [CLI reference](cli.md) — output formats and exit codes.
