// SPDX-License-Identifier: MIT
//! Category: token
//! Focus: Expose bounded token metadata from instance storage.

use soroban_sdk::{contractimpl, Env, String};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn name(env: Env) -> String {
        env.storage().instance().get(&0).unwrap()
    }

    pub fn symbol(env: Env) -> String {
        env.storage().instance().get(&1).unwrap()
    }

    pub fn decimals(env: Env) -> u32 {
        env.storage().instance().get(&2).unwrap_or(7)
    }
}
