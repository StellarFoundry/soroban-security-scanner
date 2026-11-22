// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Read and update a persistent counter while refreshing its TTL.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn increment(env: Env) -> u32 {
        let key = 0u32;
        let value: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        let next = value.checked_add(1).unwrap();
        env.storage().persistent().set(&key, &next);
        env.storage().persistent().extend_ttl(&key, 100, 1000);
        next
    }
}
