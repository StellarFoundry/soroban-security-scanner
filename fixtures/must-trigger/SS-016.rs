// SS-016 positive: repeated distinct instance-storage keys.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Settings;

#[contractimpl]
impl Settings {
    pub fn configure(env: Env, a: u32, b: u32) {
        env.storage().instance().set(&DataKey::A, &a);
        env.storage().instance().set(&DataKey::B, &b);
    }
}
