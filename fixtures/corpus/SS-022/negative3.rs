// SS-022 negative: dynamic values use Symbol::new instead of the short macro.

#![no_std]

use soroban_sdk::{contractimpl, Env, String, Symbol};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env, key: String) {
        let symbol = Symbol::new(&env, &key);
        env.storage().instance().set(&symbol, &1);
    }
}
