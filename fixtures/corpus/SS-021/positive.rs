// SS-021 positive: an owner key written to temporary storage.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Settings;

#[contractimpl]
impl Settings {
    pub fn set_owner(env: Env, owner: Address) {
        env.storage().temporary().set(&DataKey::Owner, &owner);
    }
}
