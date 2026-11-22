// SPDX-License-Identifier: MIT
//! Category: upgrade-admin
//! Focus: Record a layout version and migrate only known older versions.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn migrate(env: Env) {
        let version: u32 = env.storage().instance().get(&0).unwrap_or(1);
        if version > 2 {
            panic!("unknown storage version");
        }
        if version == 1 {
            env.storage().instance().set(&1, &0i128);
        }
        env.storage().instance().set(&0, &2u32);
    }
}
