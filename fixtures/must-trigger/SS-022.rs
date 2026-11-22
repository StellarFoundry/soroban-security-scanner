// SS-022 positive: overlong literal and caller-built short symbols.

#![no_std]

use soroban_sdk::{contractimpl, symbol_short, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn store(env: Env) {
        let key = symbol_short!("this_is_too_long");
        env.storage().instance().set(&key, &1);
    }

    pub fn store_dynamic(env: Env, key: String) {
        let symbol = symbol_short!(key);
        env.storage().instance().set(&symbol, &1);
    }
}
