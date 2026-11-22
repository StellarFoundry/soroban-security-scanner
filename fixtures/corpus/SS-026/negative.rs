// SS-026 negative: literal TTL values inside the expected range.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn put(env: Env, admin: Address, key: Symbol, value: u32) {
        admin.require_auth();
        env.storage().persistent().set(&key, &value);
        env.storage().persistent().extend_ttl(&key, 100, 1_000);
    }
}
