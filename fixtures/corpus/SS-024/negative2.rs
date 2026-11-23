// SS-024 negative: only SDK and primitive types cross the boundary.

#![no_std]

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn transfer(env: Env, from: Address, amount: i128) -> bool {
        let _ = (&env, &from, &amount);
        true
    }
}