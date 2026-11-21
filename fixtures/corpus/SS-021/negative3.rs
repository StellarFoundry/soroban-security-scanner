// SS-021 negative: a private helper is not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Settings;

#[contractimpl]
impl Settings {
    fn set_owner(env: Env, owner: Address) {
        env.storage().temporary().set(&DataKey::Owner, &owner);
    }
}
