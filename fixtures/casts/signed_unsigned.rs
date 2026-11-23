// Integer cast fixture: signedness changes are lossy even at the same width.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn reinterpret(env: Env, signed: i64, unsigned: u64) -> (u64, i64) {
        let _ = env;
        (signed as u64, unsigned as i64)
    }
}
