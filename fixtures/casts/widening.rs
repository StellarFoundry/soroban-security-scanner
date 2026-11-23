// Integer cast fixture: widening casts keep every value.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Vault;

#[contractimpl]
impl Vault {
    pub fn widen(env: Env, small: u32, signed: i32) -> (u64, i64) {
        let _ = env;
        (small as u64, signed as i64)
    }
}
