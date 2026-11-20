// SS-018 negative: widening a value read from storage.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn read(env: Env) -> u64 {
        let stored: u32 = env.storage().instance().get(&Key::Amount).unwrap();
        stored as u64
    }
}
