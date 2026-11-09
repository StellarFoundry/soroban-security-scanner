// Adversarial fixture (SS-006)
// Technique: Multiline persistent storage `.set` with comments and no TTL extension call.
// Expected: trigger (persistent storage mutation without extend_ttl/bump).

#![no_std]
use soroban_sdk::{contractimpl, symbol_short, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn record(env: Env, admin: Address, val: u64) {
        admin.require_auth();
        env
            /* comment */
            .storage()
            .persistent()
            .set(&symbol_short!("VAL"), &val);
    }
}
