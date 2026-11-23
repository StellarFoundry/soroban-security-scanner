// Integer cast fixture: narrowing casts truncate high bits.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn narrow(env: Env, amount: i128, count: u64) -> (u32, u16) {
        let _ = env;
        (amount as u32, count as u16)
    }
}
