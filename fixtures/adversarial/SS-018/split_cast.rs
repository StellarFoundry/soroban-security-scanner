// SS-018 adversarial: whitespace does not hide a narrowing cast.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn convert(env: Env, amount: i128) -> u16 {
        let _ = env;
        amount
            as
            u16
    }
}
