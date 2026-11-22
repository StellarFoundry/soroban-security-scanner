// SS-035 negative: the checked result has a fallback.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, amount: i128) -> i128 {
        amount.checked_add(1).unwrap_or(0)
    }
}
