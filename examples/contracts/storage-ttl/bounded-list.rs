// SPDX-License-Identifier: MIT
//! Category: storage-ttl
//! Focus: Keep a persistent list bounded before appending to it.

use soroban_sdk::{contractimpl, Env, Vec};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn append(env: Env, value: u32) {
        let mut items: Vec<u32> = env.storage().persistent().get(&0).unwrap_or(Vec::new(&env));
        if items.len() >= 32 {
            panic!("list is full");
        }
        items.push_back(value);
        env.storage().persistent().set(&0, &items);
        env.storage().persistent().extend_ttl(&0, 100, 1000);
    }
}
