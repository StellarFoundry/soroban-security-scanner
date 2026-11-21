// SS-021 negative: the owner is written to persistent storage.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Settings;

#[contractimpl]
impl Settings {
    pub fn set_owner(env: Env, owner: Address) {
        env.storage().persistent().set(&DataKey::Owner, &owner);
    }
}
