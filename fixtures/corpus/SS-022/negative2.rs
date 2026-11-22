// SS-022 negative: a constant identifier is not caller-controlled input.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

const KEY: &str = "balance";

#[contractimpl]
impl Contract {
    pub fn store(env: Env) {
        let key = symbol_short!(KEY);
        env.storage().instance().set(&key, &1);
    }
}
