// SS-039 negative: an intra-file helper manages the TTL.
// This file is a security fixture, not production code.

#![no_std]

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn load(env: Env) -> u32 {
        let value = env.storage().persistent().get(&0).unwrap();
        Self::bump(&env);
        value
    }

    fn bump(env: &Env) {
        env.storage().persistent().extend_ttl(&0, 100, 1_000);
    }
}
