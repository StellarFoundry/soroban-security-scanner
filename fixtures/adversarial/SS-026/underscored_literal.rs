// Adversarial SS-026: underscored and suffixed literals are still parsed, so a
// zero threshold remains out of range.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn put(env: Env, admin: Address, key: Symbol, value: u32) {
        admin.require_auth();
        env.storage().persistent().set(&key, &value);
        env.storage()
            .persistent()
            .extend_ttl(&key, 0_u32, 1_000_u32);
    }
}
