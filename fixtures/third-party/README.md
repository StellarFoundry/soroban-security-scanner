# Third-party corpus entries

Each subdirectory is one third-party contract and carries a `PROVENANCE.toml`
plus a reviewed `expected.toml`. The policy is in
[`docs/corpus-provenance.md`](../../docs/corpus-provenance.md) and is enforced
by `crates/soroban-scan-core/tests/corpus_provenance.rs` and
`crates/soroban-scan-core/tests/third_party_corpus.rs`.

The entries are pinned copies of eight Apache-2.0 contracts from
`stellar/soroban-examples` at commit
`03d42aa6b973dcf3a453a99d0c6a6e8d25a196e2`. The shared upstream license text
is in `LICENSE`. Expected findings are generated from actual scanner output
and reviewed before commit; no edges or findings are fabricated.
