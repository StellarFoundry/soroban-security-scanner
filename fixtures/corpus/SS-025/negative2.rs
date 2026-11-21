// SS-025 negative: a fixed-width numeric value is inherently bounded.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Profiles;

#[contractimpl]
impl Profiles {
    pub fn set_amount(env: Env, amount: u32) {
        env.storage().persistent().set(&DataKey::Amount, &amount);
    }
}
