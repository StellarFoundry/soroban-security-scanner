// SS-025 adversarial: whitespace inside the storage method chain does not hide
// an unbounded String parameter being persisted.

#![no_std]

use soroban_sdk::{contractimpl, Env, String};

pub struct Profiles;

#[contractimpl]
impl Profiles {
    pub fn set_name(env: Env, name: String) {
        env . storage () . persistent () . set (& DataKey :: Name, & name);
    }
}
