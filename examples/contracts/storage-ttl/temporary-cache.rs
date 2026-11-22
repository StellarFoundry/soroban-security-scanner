// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Use temporary storage only for data that may be discarded.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn remember(env: Env, value: u32) {
        env.storage().temporary().set(&0, &value);
        env.storage().temporary().extend_ttl(&0, 100, 200);
    }
}
