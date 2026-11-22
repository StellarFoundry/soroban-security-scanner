// SS-025 negative: the string length is checked before persisting.

#![no_std]

use soroban_sdk::{contractimpl, Env, String};

pub struct Profiles;

#[contractimpl]
impl Profiles {
    pub fn set_name(env: Env, name: String) {
        if name.len() > 64 {
            panic!("name too long");
        }
        env.storage().persistent().set(&DataKey::Name, &name);
    }
}
