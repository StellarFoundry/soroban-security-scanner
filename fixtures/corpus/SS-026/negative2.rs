// SS-026 negative: TTL arguments are computed values, not literals.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn put(
        env: Env,
        admin: Address,
        key: Symbol,
        threshold: u32,
        bump: u32,
    ) {
        admin.require_auth();
        env.storage().persistent().extend_ttl(&key, threshold, bump);
    }
}
