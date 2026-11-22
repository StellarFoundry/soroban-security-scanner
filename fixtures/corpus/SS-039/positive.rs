// SS-039 positive: a persistent read has no TTL extension in the entry point.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn load(env: Env) -> u32 {
        env.storage().persistent().get(&0).unwrap()
    }
}
