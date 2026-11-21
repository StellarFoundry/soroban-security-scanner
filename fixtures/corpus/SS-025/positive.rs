// SS-025 positive: a caller-supplied string is persisted without a bound.

#![no_std]

use soroban_sdk::{contractimpl, Env, String};

pub struct Profiles;

#[contractimpl]
impl Profiles {
    pub fn set_name(env: Env, name: String) {
        env.storage().persistent().set(&DataKey::Name, &name);
    }
}
