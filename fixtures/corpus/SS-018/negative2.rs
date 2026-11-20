// SS-018 negative: a fallible conversion instead of `as`.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn set_amount(env: Env, amount: i128) -> u32 {
        let _ = env;
        u32::try_from(amount).unwrap_or(0)
    }
}
