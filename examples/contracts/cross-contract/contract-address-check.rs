// SPDX-License-Identifier: MIT
//! Category: cross-contract
//! Focus: Compare a supplied contract address with stored configuration.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn call(env: Env, target: Address) {
        let configured: Address = env.storage().instance().get(&0).unwrap();
        if target != configured {
            panic!("unexpected contract");
        }
        let _ = env.invoke_contract::<()>(&target, &soroban_sdk::Symbol::new(&env, "ping"), soroban_sdk::Vec::new(&env));
    }
}
