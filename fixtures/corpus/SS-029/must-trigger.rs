// Must-trigger recall fixture (SS-029)
// Rationale: True positive because `test_reset_state` is a public `#[contractimpl]`
// entry point whose name starts with `test_`, exposing a debug/test backdoor in
// production WASM builds.

#![no_std]
use soroban_sdk::{contractimpl, Address, Env};

pub struct ProductionVault;

#[contractimpl]
impl ProductionVault {
    pub fn test_reset_state(_env: Env, caller: Address) {
        let _ = caller;
    }
}
