// SS-018 positive: narrowing a caller-supplied integer with `as`.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn set_amount(env: Env, amount: i128) -> u32 {
        let _ = env;
        amount as u32
    }
}
