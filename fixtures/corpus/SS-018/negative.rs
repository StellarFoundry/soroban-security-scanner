// SS-018 negative: widening a parameter cast.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn widen(env: Env, amount: u32) -> u64 {
        let _ = env;
        amount as u64
    }
}
