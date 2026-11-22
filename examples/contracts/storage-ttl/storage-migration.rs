// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Record a storage schema version before migrating entries.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn migrate(env: Env) {
        let version: u32 = env.storage().instance().get(&9).unwrap_or(0);
        if version < 2 {
            env.storage().instance().set(&9, &2u32);
            env.storage().persistent().extend_ttl(&9, 100, 10_000);
        }
    }
}
