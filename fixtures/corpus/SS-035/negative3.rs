// SS-035 negative: a private helper is not an entry point.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    fn deposit(env: Env, amount: i128) {
        let _ = amount.checked_add(1);
    }
}
