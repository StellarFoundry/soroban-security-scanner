// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Extend a persistent entry that must survive long-lived escrow.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn keep_alive(env: Env, key: u32) {
        if env.storage().persistent().has(&key) {
            env.storage().persistent().extend_ttl(&key, 17_280, 518_400);
        }
    }
}
