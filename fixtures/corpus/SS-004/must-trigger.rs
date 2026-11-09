// Must-trigger recall fixture (SS-004)
// Rationale: True positive because `force_read` calls `.unwrap()` on a storage
// lookup and invokes `panic!` directly inside a public entry point instead of
// returning a typed `#[contracterror]` result.

#![no_std]
use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct VaultConfig;

#[contractimpl]
impl VaultConfig {
    pub fn force_read(env: Env) -> u64 {
        let limit: u64 = env.storage().instance().get(&symbol_short!("LIMIT")).unwrap();
        if limit == 0 {
            panic!("zero limit");
        }
        limit
    }
}
