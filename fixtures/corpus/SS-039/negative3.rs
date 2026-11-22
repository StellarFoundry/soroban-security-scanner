// SS-039 negative: temporary storage is allowed to expire.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn load(env: Env) -> u32 {
        env.storage().temporary().get(&0).unwrap()
    }
}
