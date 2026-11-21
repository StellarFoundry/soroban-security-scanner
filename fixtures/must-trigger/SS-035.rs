// SS-035 positive: the checked arithmetic result is discarded.
#![no_std]
use soroban_sdk::{contractimpl, Env};
pub struct C;
#[contractimpl]
impl C {
    pub fn add(_env: Env, amount: i128) {
        amount.checked_add(1);
    }
}
