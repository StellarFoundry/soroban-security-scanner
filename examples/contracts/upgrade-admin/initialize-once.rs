// SPDX-License-Identifier: MIT
//! Category: upgrade-admin
//! Focus: Initialize configuration exactly once.

use soroban_sdk::{contractimpl, Address, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&0) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&0, &admin);
    }
}
