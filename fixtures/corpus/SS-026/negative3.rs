// SS-026 negative: set_ttl uses a literal inside the expected range.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env, Symbol};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn put(env: Env, admin: Address, key: Symbol, value: u32) {
        admin.require_auth();
        env.storage().persistent().set(&key, &value);
        env.storage().persistent().set_ttl(&key, 518_400);
    }
}
