// SS-035 negative: the result is propagated with `?` or matched.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn deposit(env: Env, amount: i128) -> Option<i128> {
        let raised = amount.checked_add(1)?;
        let lowered = match amount.checked_sub(1) {
            Some(value) => value,
            None => 0,
        };
        Some(raised + lowered)
    }
}
