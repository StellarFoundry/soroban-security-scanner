// SS-017 positive: storage mutation before authorization.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn set(env: Env, admin: Address, value: u32) {
        env.storage().persistent().set(&DataKey::Value, &value);
        admin.require_auth();
    }
}
