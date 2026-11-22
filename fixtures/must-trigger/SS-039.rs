// SS-039 must trigger: a persistent read has no TTL extension in the entry
// point or its intra-file helpers.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn load(env: Env) -> u32 {
        env.storage().persistent().get(&0).unwrap()
    }
}
