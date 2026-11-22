// SS-039 negative: instance storage is not the persistent storage class.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn load(env: Env) -> u32 {
        env.storage().instance().get(&0).unwrap()
    }
}
