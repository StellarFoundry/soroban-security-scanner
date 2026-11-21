// SS-022 negative: a valid nine-character short literal.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env) {
        let key = symbol_short!("123456789");
        env.storage().instance().set(&key, &1);
    }
}
