// SS-035 positive: the checked result is discarded into `_`.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, amount: i128) {
        let _ = amount.checked_add(1);
    }
}
