# Monorepo fixture

Synthetic security fixture for monorepo path filtering (`#343`); not
production code. Every project's `src/` holds one SS-001 trigger so tests can
tell from the findings which projects were scanned:

```
.                         root workspace (no sources of its own)
contracts/                nested workspace
contracts/token/          member
contracts/vault/          member
contracts/vault/adapter/  crate nested inside a member
tools/gen/                tool crate
```
