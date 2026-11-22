// SS-021 positive: durable ownership data must not use expiring temporary storage.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn set_owner(env: Env, owner: Address) {
        env.storage().temporary().set(&DataKey::Owner, &owner);
    }
}
