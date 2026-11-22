# Example contract corpus

Fifty small, standalone Soroban contracts used for documentation, manual
review, and detector calibration. Each file is source-only: the scanner
parses these examples but never compiles, executes, deploys, or signs them.

Every example is MIT licensed (matching the repository), and carries its
category and focus in the file header:

```rust
// SPDX-License-Identifier: MIT
//! Category: authorization
//! Focus: Require the stored administrator's authorization before a privileged write.
```

The corpus currently contains **50** contracts across 8 categories.

| Category | Example | Focus |
| -------- | ------- | ----- |
| arithmetic | [balance-accounting](arithmetic/balance-accounting.rs) | Keep debit and credit sides of an accounting entry consistent. |
| arithmetic | [checked-add](arithmetic/checked-add.rs) | Use checked addition and reject overflow explicitly. |
| arithmetic | [checked-mul](arithmetic/checked-mul.rs) | Use checked multiplication before storing a computed total. |
| arithmetic | [checked-sub](arithmetic/checked-sub.rs) | Use checked subtraction to prevent negative balances. |
| arithmetic | [percentage-fee](arithmetic/percentage-fee.rs) | Compute a fee with checked multiplication and division. |
| arithmetic | [safe-cast](arithmetic/safe-cast.rs) | Convert a wide amount to a narrow type with try_into. |
| authorization | [admin-auth](authorization/admin-auth.rs) | Require the stored administrator's authorization before a privileged write. |
| authorization | [auth-for-args](authorization/auth-for-args.rs) | Authorize an operation and bind approval to its exact arguments. |
| authorization | [auth-in-helper](authorization/auth-in-helper.rs) | Move authorization into an intra-file helper without dropping it. |
| authorization | [missing-admin-auth](authorization/missing-admin-auth.rs) | Show a privileged write that forgets authorization (intentionally unsafe). |
| authorization | [multisig-threshold](authorization/multisig-threshold.rs) | Collect approvals from a fixed signer set until a threshold is met. |
| authorization | [operator-allowance](authorization/operator-allowance.rs) | Bind an operator to an allowance that the owner authorizes once. |
| authorization | [role-check](authorization/role-check.rs) | Check a stored role before allowing an operator action. |
| authorization | [two-step-ownership](authorization/two-step-ownership.rs) | Transfer ownership through a propose and accept handshake. |
| cross-contract | [callback-guard](cross-contract/callback-guard.rs) | Guard a cross-contract callback with a one-shot flag. |
| cross-contract | [client-call](cross-contract/client-call.rs) | Call a configured contract through a typed client. |
| cross-contract | [contract-address-check](cross-contract/contract-address-check.rs) | Compare a supplied contract address with stored configuration. |
| cross-contract | [factory-deploy](cross-contract/factory-deploy.rs) | Deploy a child contract only after administrator authorization. |
| cross-contract | [interface-dispatch](cross-contract/interface-dispatch.rs) | Dispatch to one of two configured contracts based on a route key. |
| cross-contract | [reentrancy-guard](cross-contract/reentrancy-guard.rs) | Set a reentrancy lock before making an external call. |
| errors | [invalid-input](errors/invalid-input.rs) | Reject an out-of-range input before it reaches storage. |
| errors | [invariant-guard](errors/invariant-guard.rs) | Assert an invariant after updating two related entries. |
| errors | [typed-error](errors/typed-error.rs) | Return a typed contract error instead of a string panic. |
| errors | [unauthorized-error](errors/unauthorized-error.rs) | Return an authorization error with a typed variant. |
| events | [admin-event](events/admin-event.rs) | Emit an event when privileged configuration changes. |
| events | [deposit-event](events/deposit-event.rs) | Publish a structured deposit event after a successful transfer. |
| events | [indexed-topic](events/indexed-topic.rs) | Index a caller address as the event topic for filtering. |
| events | [no-sensitive-event](events/no-sensitive-event.rs) | Publish only a reference, never secret material, in an event. |
| storage-ttl | [bounded-list](storage-ttl/bounded-list.rs) | Keep a persistent list bounded before appending to it. |
| storage-ttl | [extend-ttl](storage-ttl/extend-ttl.rs) | Extend a persistent entry that must survive long-lived escrow. |
| storage-ttl | [instance-config](storage-ttl/instance-config.rs) | Store bounded configuration in instance storage for cheap access. |
| storage-ttl | [nested-map](storage-ttl/nested-map.rs) | Key persistent balances by address in a bounded map. |
| storage-ttl | [persistent-counter](storage-ttl/persistent-counter.rs) | Read and update a persistent counter while refreshing its TTL. |
| storage-ttl | [storage-migration](storage-ttl/storage-migration.rs) | Record a storage schema version before migrating entries. |
| storage-ttl | [temporary-cache](storage-ttl/temporary-cache.rs) | Use temporary storage only for data that may be discarded. |
| storage-ttl | [ttl-guard](storage-ttl/ttl-guard.rs) | Refresh a persistent entry when its TTL drops below a threshold. |
| token | [burn-holder](token/burn-holder.rs) | Burn from the holder's own balance after their authorization. |
| token | [checked-transfer-amount](token/checked-transfer-amount.rs) | Reject non-positive transfer amounts before calling a token. |
| token | [clawback-admin](token/clawback-admin.rs) | Allow a controlled clawback only for the configured administrator. |
| token | [fungible-transfer](token/fungible-transfer.rs) | Move tokens only after the sender authorizes the transfer. |
| token | [mint-admin](token/mint-admin.rs) | Restrict minting to the administrator and extend the balance TTL. |
| token | [token-client-call](token/token-client-call.rs) | Query an external token's balance through a typed client. |
| token | [token-metadata](token/token-metadata.rs) | Expose bounded token metadata from instance storage. |
| token | [transfer-from-allowance](token/transfer-from-allowance.rs) | Spend a pre-approved allowance through transfer_from. |
| upgrade-admin | [emergency-stop](upgrade-admin/emergency-stop.rs) | Stop operations irreversibly after an emergency. |
| upgrade-admin | [fee-config](upgrade-admin/fee-config.rs) | Update a bounded fee only through the administrator. |
| upgrade-admin | [initialize-once](upgrade-admin/initialize-once.rs) | Initialize configuration exactly once. |
| upgrade-admin | [pause-switch](upgrade-admin/pause-switch.rs) | Gate state changes behind an administrator pause switch. |
| upgrade-admin | [upgrade-admin](upgrade-admin/upgrade-admin.rs) | Authorize upgrades with the stored administrator. |
| upgrade-admin | [versioned-storage](upgrade-admin/versioned-storage.rs) | Record a layout version and migrate only known older versions. |

## Validate

```bash
python tools/check_examples.py
```

The check enforces the license header, directory-derived category, a
non-empty focus, a `#[contractimpl]` block, and the minimum corpus size.
