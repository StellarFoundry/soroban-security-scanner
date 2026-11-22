// SPDX-License-Identifier: MIT
//! Category: arithmetic
//! Focus: Use checked addition and reject overflow explicitly.

use soroban_sdk::{contractimpl, Env};

pub struct Contract;

#[contractimpl]
impl Contract {
    pub fn add(env: Env, a: i128, b: i128) -> i128 {
        let sum = a.checked_add(b).expect("overflow");
        env.storage().instance().set(&0, &sum);
        sum
    }
}
