// SS-025 negative: a private helper is not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, Env, String};

pub struct Profiles;

#[contractimpl]
impl Profiles {
    fn set_name(env: Env, name: String) {
        env.storage().persistent().set(&DataKey::Name, &name);
    }
}
