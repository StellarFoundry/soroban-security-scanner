// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Refresh a persistent entry when its TTL drops below a threshold.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn touch(env: Env, key: u32) {
        let ttl = env.storage().persistent().get_ttl(&key);
        if ttl < 1_000 {
            env.storage().persistent().extend_ttl(&key, 5_000, 100_000);
        }
    }
}
